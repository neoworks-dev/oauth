<script>
  // Password sign-in. The password is stretched in the browser; only a derived key is sent.

  import Marmot from "./Marmot.svelte"
  import { finishSignIn, signInWithPassword } from "./signIn.js"
  import { createStepRunner } from "./stepRunner.svelte.js"

  let { context, onDone } = $props()

  const step = createStepRunner()
  let email = $state("")
  let password = $state("")
  let rememberBrowser = $state(true)

  const marmotPose = $derived.by(() => {
    if (step.errorMessage) {
      return "stop"
    }
    return "waving"
  })

  const subtitle = $derived.by(() => {
    if (context.challenge) {
      return "Sign in to continue to " + context.challenge.clientName
    }
    return "Sign in to your account"
  })

  // The sign-up page keeps the pending authorization request, when there is one.
  const signupPath = $derived.by(() => {
    if (context.challengeId) {
      return "/signup?login_challenge=" + encodeURIComponent(context.challengeId)
    }
    return "/signup"
  })

  function goTo(clickEvent, path) {
    clickEvent.preventDefault()
    context.navigate(path)
  }

  async function signIn(submitEvent) {
    submitEvent.preventDefault()
    await step.run(async () => {
      const { login, accountKey } = await signInWithPassword(email.trim(), password)
      await finishSignIn(login, accountKey, rememberBrowser)
      onDone()
    })
  }
</script>

<Marmot pose={marmotPose} />
<h1>Sign in</h1>
<p class="subtitle">{subtitle}</p>

<form onsubmit={signIn}>
  {#if step.errorMessage}<p class="error" role="alert">{step.errorMessage}</p>{/if}

  <div class="field">
    <label for="email">Email</label>
    <input id="email" type="email" placeholder="you@example.com" autocomplete="username" required bind:value={email} />
  </div>

  <div class="field">
    <label for="password">Password</label>
    <input
      id="password"
      type="password"
      placeholder="Your password"
      autocomplete="current-password"
      required
      bind:value={password}
    />
  </div>

  <div class="checkbox-row">
    <input type="checkbox" id="remember" bind:checked={rememberBrowser} />
    <label for="remember">Remember this browser</label>
  </div>

  <button type="submit" disabled={step.isBusy}>
    {#if step.isBusy}Signing in…{:else}Sign in{/if}
  </button>
</form>

<p class="signin-link">
  <a href="/recover" onclick={(clickEvent) => goTo(clickEvent, "/recover")}>Forgot your password?</a>
</p>
<p class="signin-link">
  New to Neoworks? <a href={signupPath} onclick={(clickEvent) => goTo(clickEvent, signupPath)}>Create an account</a>
</p>
