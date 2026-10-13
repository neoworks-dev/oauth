<script>
  // Recovery with Neoworks's help: start a recovery, wait, then claim the account key,
  // which is sealed to a temporary key kept on this browser.

  import { ApiError, describeError, postJson } from "$legacy/nw-api.js"
  import { clearAttempt, loadAttempt, saveAttempt } from "$legacy/nw-escrow-store.js"
  import { boxKeypair, decodeBase64Url, encodeBase64Url, sealOpen, wipe } from "$legacy/nw-primitives.js"
  import { createStepRunner } from "./stepRunner.svelte.js"

  // released: the verified-email response of the forgot-password flow.
  // onAccountKey: called with the account key once the recovery is complete.
  let { released, onAccountKey } = $props()

  const step = createStepRunner()
  let statusText = $state(
    "Neoworks can restore your access after a waiting period. Anyone who breaks into or legally compels us could do the same, which is why you chose this option.",
  )

  function formatDate(isoText) {
    return new Date(isoText).toLocaleString()
  }

  async function startRecovery() {
    const temporaryKeys = boxKeypair()
    const started = await postJson("/vault/escrow/recovery/start", {
      resetToken: released.resetToken,
      tempPub: encodeBase64Url(temporaryKeys.publicKey),
    })
    await saveAttempt(released.bundle.userId, {
      attemptId: started.id,
      claimSecret: started.claimSecret,
      readyAt: started.readyAt,
      tempPub: encodeBase64Url(temporaryKeys.publicKey),
      tempSecret: temporaryKeys.secretKey,
    })
    wipe(temporaryKeys.secretKey)
    statusText =
      "We emailed you. Access can be restored on " + formatDate(started.readyAt) +
      ". Come back then, verify your email again and choose this option to finish. You can cancel from any signed-in device or the email."
  }

  // Returns the account key, or null when the waiting period is not over yet.
  async function claimRecovery(attempt) {
    try {
      const claimed = await postJson("/vault/escrow/recovery/claim", {
        resetToken: released.resetToken,
        attemptId: attempt.attemptId,
        claimSecret: attempt.claimSecret,
      })
      return sealOpen(decodeBase64Url(attempt.tempPub), attempt.tempSecret, decodeBase64Url(claimed.sealed))
    } catch (error) {
      if (error instanceof ApiError && error.code === "not_ready") {
        statusText = "Access can be restored on " + formatDate(attempt.readyAt) + ". Please come back then."
        return null
      }
      throw error
    }
  }

  // The first press starts the recovery; later presses try to claim it.
  async function continueRecovery() {
    const userId = released.bundle.userId
    const attempt = await loadAttempt(userId)
    if (attempt === null) {
      await startRecovery()
      return
    }
    const accountKey = await claimRecovery(attempt)
    if (accountKey === null) {
      return
    }
    await clearAttempt(userId)
    onAccountKey(accountKey)
  }
</script>

<div>
  <p class="hint" id="escrow-status">{statusText}</p>
  {#if step.errorMessage}<p class="error" role="alert">{step.errorMessage}</p>{/if}
  <button type="button" class="secondary" id="escrow-recover" disabled={step.isBusy} onclick={() => step.run(continueRecovery)}>
    {#if step.isBusy}Working…{:else}Ask Neoworks to help{/if}
  </button>
</div>
