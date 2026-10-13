<script>
  // Forgot password: prove the email, then unwrap the account key with the recovery key
  // (or with Neoworks's help) and set a new password.
  //
  // Steps: email -> code -> method -> password.

  import {
    derivePasswordKeys,
    deriveRecoveryKek,
    newPwhashParams,
    unwrapAmk,
    unwrapIdentity,
    wrapAmk,
  } from "$legacy/nw-account.js"
  import { postJson } from "$legacy/nw-api.js"
  import { parseRecoveryWords } from "$legacy/nw-recovery.js"
  import { decodeBase64Url, encodeBase64Url, wipe } from "$legacy/nw-primitives.js"
  import Marmot from "./Marmot.svelte"
  import RecoverEscrow from "./RecoverEscrow.svelte"
  import { createStepRunner } from "./stepRunner.svelte.js"

  const MINIMUM_PASSWORD_LENGTH = 8

  let { context } = $props()

  const step = createStepRunner()
  let currentStep = $state("email")

  let email = $state("")
  let verificationCode = $state("")
  let developmentCode = $state("")
  let recoveryWords = $state("")
  let newPassword = $state("")

  // What the server released once the email was verified, and the unwrapped account key.
  let released = $state.raw(null)
  let accountKey = null

  const escrowIsOffered = $derived(
    currentStep === "method" && released.escrowEnabled && context.boot.escrowAvailable,
  )
  const signinPath = $derived("/signin" + context.challengeQuery)

  const marmotPose = $derived.by(() => {
    if (step.errorMessage) {
      return "stop"
    }
    const poseByStep = { email: "lost", code: "peeking", method: "locked", password: "locked" }
    return poseByStep[currentStep]
  })

  function goToSignin(clickEvent) {
    clickEvent.preventDefault()
    context.navigate(signinPath)
  }

  async function sendCode(submitEvent) {
    submitEvent.preventDefault()
    email = email.trim()
    await step.run(async () => {
      const sent = await postJson("/vault/forgot/send-code", { email })
      developmentCode = ""
      if (sent.code) {
        developmentCode = sent.code
      }
      currentStep = "code"
    })
  }

  async function verifyCode(submitEvent) {
    submitEvent.preventDefault()
    await step.run(async () => {
      released = await postJson("/vault/forgot/verify-code", { email, code: verificationCode.trim() })
      currentStep = "method"
    })
  }

  // Unwraps the account key and checks that it opens the identity.
  function openWithRecoveryKey(wordsText) {
    const entropy = parseRecoveryWords(wordsText)
    const bundle = released.bundle
    const key = unwrapAmk(deriveRecoveryKek(entropy), decodeBase64Url(bundle.amkRecovery), bundle.userId, "recovery")
    unwrapIdentity(key, bundle)
    wipe(entropy)
    return key
  }

  async function useRecoveryKey(submitEvent) {
    submitEvent.preventDefault()
    await step.run(
      async () => {
        accountKey = openWithRecoveryKey(recoveryWords)
        currentStep = "password"
      },
      () => "That recovery key does not match this account.",
    )
  }

  function useEscrowKey(escrowAccountKey) {
    accountKey = escrowAccountKey
    currentStep = "password"
  }

  async function resetPassword() {
    const passwordParameters = newPwhashParams()
    const keys = derivePasswordKeys(newPassword, passwordParameters)
    const wrappedAccountKey = encodeBase64Url(wrapAmk(keys.passwordKEK, accountKey, released.bundle.userId, "password"))
    await postJson("/vault/forgot/reset", {
      resetToken: released.resetToken,
      newAuthKey: encodeBase64Url(keys.authKey),
      pwhash: passwordParameters,
      amkPassword: wrappedAccountKey,
      expectedVersion: released.bundle.version,
    })
    wipe(keys.authKey)
    wipe(keys.passwordKEK)
    wipe(accountKey)
  }

  async function setNewPassword(submitEvent) {
    submitEvent.preventDefault()
    if (newPassword.length < MINIMUM_PASSWORD_LENGTH) {
      step.errorMessage = "Password must be at least " + MINIMUM_PASSWORD_LENGTH + " characters."
      return
    }
    await step.run(async () => {
      await resetPassword()
      context.navigate(signinPath)
    })
  }
</script>

<Marmot pose={marmotPose} />

{#if currentStep === "email"}
  <h1>Reset your password</h1>
  <p class="subtitle">We will email you a code. You will also need your recovery key.</p>

  <form onsubmit={sendCode}>
    {#if step.errorMessage}<p class="error" role="alert">{step.errorMessage}</p>{/if}
    <div class="field">
      <label for="email">Email</label>
      <input id="email" type="email" placeholder="you@example.com" autocomplete="email" required bind:value={email} />
    </div>
    <button type="submit" disabled={step.isBusy}>
      {#if step.isBusy}Sending…{:else}Send code{/if}
    </button>
  </form>

  <p class="signin-link"><a href={signinPath} onclick={goToSignin}>Back to sign in</a></p>
{:else if currentStep === "code"}
  <h1>Check your email</h1>
  <p class="subtitle">Enter the 6-digit code sent to {email}.</p>

  <form onsubmit={verifyCode}>
    {#if step.errorMessage}<p class="error" role="alert">{step.errorMessage}</p>{/if}
    <div class="field">
      <label for="code">Verification code</label>
      <input
        id="code"
        type="text"
        inputmode="numeric"
        placeholder="6-digit code"
        autocomplete="one-time-code"
        required
        bind:value={verificationCode}
      />
    </div>
    <button type="submit" disabled={step.isBusy}>
      {#if step.isBusy}Verifying…{:else}Verify{/if}
    </button>
  </form>

  <p class="hint" id="debug-code">
    {#if developmentCode}Development code: {developmentCode}{/if}
  </p>
{:else if currentStep === "method"}
  <h1>Use your recovery key</h1>
  <p class="subtitle">Enter the words you saved when you created your account.</p>

  <form onsubmit={useRecoveryKey}>
    {#if step.errorMessage}<p class="error" role="alert">{step.errorMessage}</p>{/if}
    <div class="field">
      <label for="recovery-words-input">Recovery key</label>
      <textarea
        id="recovery-words-input"
        rows="4"
        placeholder="Enter your recovery key words"
        required
        bind:value={recoveryWords}
      ></textarea>
    </div>
    <button type="submit" disabled={step.isBusy}>
      {#if step.isBusy}Checking…{:else}Continue{/if}
    </button>
  </form>

  {#if escrowIsOffered}
    <div class="divider">or</div>
    <RecoverEscrow {released} onAccountKey={useEscrowKey} />
  {/if}
{:else}
  <h1>Choose a new password</h1>
  <p class="subtitle">Your data stays encrypted with the same key.</p>

  <form onsubmit={setNewPassword}>
    {#if step.errorMessage}<p class="error" role="alert">{step.errorMessage}</p>{/if}
    <div class="field">
      <label for="new-password">New password</label>
      <input
        id="new-password"
        type="password"
        placeholder="Choose a new password"
        autocomplete="new-password"
        required
        bind:value={newPassword}
      />
    </div>
    <button type="submit" disabled={step.isBusy}>
      {#if step.isBusy}Saving…{:else}Set password{/if}
    </button>
  </form>
{/if}
