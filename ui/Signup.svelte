<script>
  // Steps: account -> code -> (escrow, only when offered) -> keys -> recovery key.
  // The recovery key screen is still a plain view, so this component hands over to it.

  import { describeError, getJson, postJson } from "$legacy/nw-api.js"
  import { describeBrowser } from "$legacy/nw-browser.js"
  import { h as createElement } from "$legacy/nw-dom.js"
  import { ESCROW_PUBLIC_KEY } from "$legacy/escrow-key.js"
  import { getDeviceId, saveDeviceWrap, unlock } from "$legacy/nw-keystore.js"
  import { createSignupMaterial } from "$legacy/nw-signup-material.js"
  import EscrowChoice from "./EscrowChoice.svelte"
  import Marmot from "./Marmot.svelte"
  import { renderRecoveryKeyConfirmation } from "./recoveryKey.js"

  const MINIMUM_PASSWORD_LENGTH = 8

  // Lets the "Creating your keys" screen paint before key derivation blocks the page.
  const KEY_SCREEN_DELAY_MILLISECONDS = 50

  let { context, unmountView, onDone } = $props()

  let currentStep = $state("account")
  let isBusy = $state(false)
  let errorMessage = $state("")

  // Only returned by the server in debug mode.
  let developmentCode = $state("")

  let firstName = $state("")
  let lastName = $state("")
  let email = $state("")
  let password = $state("")
  let passwordConfirmation = $state("")
  let verificationCode = $state("")
  let wantsEscrowRecovery = $state(false)

  const escrowIsOffered = $derived(context.boot.escrowAvailable && ESCROW_PUBLIC_KEY !== null)
  const signinPath = $derived("/signin" + context.challengeQuery)

  const subtitle = $derived.by(() => {
    if (context.challenge) {
      return "Sign up to continue to " + context.challenge.clientName
    }
    return "Get started with Neoworks"
  })

  const marmotPose = $derived.by(() => {
    if (errorMessage) {
      return "stop"
    }
    const poseByStep = { account: "waving", code: "peeking", escrow: "locked", keys: "digging" }
    return poseByStep[currentStep]
  })

  // The two options sit side by side, so the card is wider on that screen.
  $effect(() => {
    context.root.classList.toggle("choices", currentStep === "escrow")
    return () => context.root.classList.remove("choices")
  })

  function goToSignin(clickEvent) {
    clickEvent.preventDefault()
    context.navigate(signinPath)
  }

  async function runStep(action) {
    errorMessage = ""
    isBusy = true
    try {
      await action()
    } catch (error) {
      errorMessage = describeError(error)
    } finally {
      isBusy = false
    }
  }

  async function requestVerificationCode(submitEvent) {
    submitEvent.preventDefault()
    firstName = firstName.trim()
    lastName = lastName.trim()
    email = email.trim()

    if (password.length < MINIMUM_PASSWORD_LENGTH) {
      errorMessage = "Password must be at least " + MINIMUM_PASSWORD_LENGTH + " characters."
      return
    }

    if (password !== passwordConfirmation) {
      errorMessage = "The passwords do not match."
      return
    }

    await runStep(async () => {
      const response = await postJson("/vault/signup/send-code", { email })
      developmentCode = ""
      if (response.code) {
        developmentCode = response.code
      }
      currentStep = "code"
    })
  }

  async function verifyEmailCode(submitEvent) {
    submitEvent.preventDefault()

    await runStep(async () => {
      await postJson("/vault/signup/verify-code", { email, code: verificationCode.trim() })
      if (escrowIsOffered) {
        currentStep = "escrow"
        return
      }
      createKeys({ withEscrow: false })
    })
  }

  async function createKeys({ withEscrow }) {
    currentStep = "keys"
    await new Promise((resolve) => setTimeout(resolve, KEY_SCREEN_DELAY_MILLISECONDS))

    let escrowPublicKey = null
    if (withEscrow) {
      escrowPublicKey = ESCROW_PUBLIC_KEY
    }

    const signupMaterial = createSignupMaterial({
      email,
      firstName,
      lastName,
      password,
      deviceId: await getDeviceId(),
      deviceName: describeBrowser(),
      escrowPublicKey,
    })

    // Nothing needs the password once the keys exist.
    password = ""
    passwordConfirmation = ""
    showRecoveryKey(signupMaterial)
  }

  // The plain recovery key view takes over the page, so this component unmounts first.
  function showRecoveryKey(signupMaterial) {
    const rememberBrowserCheckbox = createElement("input", { type: "checkbox", id: "remember", checked: true })
    const rememberBrowserRow = createElement(
      "div",
      { class: "checkbox-row" },
      rememberBrowserCheckbox,
      createElement("label", { for: "remember" }, "Remember this browser"),
    )

    unmountView()
    renderRecoveryKeyConfirmation(context, {
      words: signupMaterial.recoveryWords,
      confirmLabel: "Create account",
      extras: [rememberBrowserRow],
      onConfirm: () => createAccount(signupMaterial, rememberBrowserCheckbox.checked),
    })
  }

  async function createAccount(signupMaterial, rememberThisBrowser) {
    await postJson("/vault/signup", signupMaterial.request)
    const keyBundle = await getJson("/vault/bundle")
    unlock(signupMaterial.amk, keyBundle)

    if (rememberThisBrowser) {
      await saveDeviceWrap(signupMaterial.userId, signupMaterial.amk)
    }
    onDone()
  }
</script>

{#if currentStep === "account"}
  <Marmot pose={marmotPose} />
  <h1>Create account</h1>
  <p class="subtitle">{subtitle}</p>

  <form onsubmit={requestVerificationCode}>
    {#if errorMessage}<p class="error" role="alert">{errorMessage}</p>{/if}

    <div class="row">
      <div class="field">
        <label for="first-name">First name</label>
        <input id="first-name" type="text" placeholder="Ada" autocomplete="given-name" required bind:value={firstName} />
      </div>
      <div class="field">
        <label for="last-name">Last name</label>
        <input id="last-name" type="text" placeholder="Lovelace" autocomplete="family-name" required bind:value={lastName} />
      </div>
    </div>

    <div class="field">
      <label for="email">Email</label>
      <input id="email" type="email" placeholder="you@example.com" autocomplete="email" required bind:value={email} />
    </div>

    <div class="field">
      <label for="password">Password</label>
      <input id="password" type="password" placeholder="At least 8 characters" autocomplete="new-password" required bind:value={password} />
    </div>

    <div class="field">
      <label for="password-confirm">Confirm password</label>
      <input
        id="password-confirm"
        type="password"
        placeholder="Repeat your password"
        autocomplete="new-password"
        required
        bind:value={passwordConfirmation}
      />
    </div>

    <button type="submit" disabled={isBusy}>
      {#if isBusy}Sending code…{:else}Continue{/if}
    </button>
  </form>

  <p class="signin-link">
    Already have an account? <a href={signinPath} onclick={goToSignin}>Sign in</a>
  </p>
{:else if currentStep === "code"}
  <Marmot pose={marmotPose} />
  <h1>Verify your email</h1>
  <p class="subtitle">We sent a 6-digit code to {email}.</p>

  <form onsubmit={verifyEmailCode}>
    {#if errorMessage}<p class="error" role="alert">{errorMessage}</p>{/if}

    <div class="field">
      <label for="code">Verification code</label>
      <input id="code" type="text" inputmode="numeric" placeholder="6-digit code" autocomplete="one-time-code" required bind:value={verificationCode} />
    </div>

    <button type="submit" disabled={isBusy}>
      {#if isBusy}Verifying…{:else}Verify email{/if}
    </button>
  </form>

  <p class="hint" id="debug-code">
    {#if developmentCode}Development code: {developmentCode}{/if}
  </p>
{:else if currentStep === "escrow"}
  <Marmot pose={marmotPose} />
  <h1>Protect your account</h1>
  <p class="subtitle">Choose what happens if you lose access. You can change this later in settings.</p>

  <EscrowChoice bind:wantsEscrow={wantsEscrowRecovery} />

  <button type="button" id="escrow-continue" onclick={() => createKeys({ withEscrow: wantsEscrowRecovery })}>
    Continue
  </button>
{:else}
  <Marmot pose={marmotPose} />
  <h1>Creating your keys…</h1>
  <p class="subtitle">Your keys are generated in this browser.</p>

{/if}
