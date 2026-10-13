<script>
  // The page behind the cancel link in the recovery notification email. The attempt id and
  // token travel in the URL fragment so they never reach server logs.

  import { describeError, postJson } from "$legacy/nw-api.js"
  import Marmot from "./Marmot.svelte"
  import { createStepRunner } from "./stepRunner.svelte.js"

  const step = createStepRunner()
  let wasCancelled = $state(false)

  const fragment = new URLSearchParams(location.hash.slice(1))
  const attemptId = fragment.get("a")
  const token = fragment.get("t")
  const linkIsComplete = attemptId !== null && token !== null

  async function cancelRecovery() {
    await step.run(async () => {
      await postJson("/vault/escrow/recovery/cancel", { attemptId, token })
      wasCancelled = true
    })
  }
</script>

{#if linkIsComplete}
  <Marmot pose="stop" />
  <h1>Cancel account recovery</h1>
  <p class="subtitle">
    Someone asked Neoworks to restore access to your account. If this was not you, cancel it.
  </p>
  <button type="button" id="cancel-recovery" disabled={step.isBusy || wasCancelled} onclick={cancelRecovery}>
    {#if step.isBusy}Cancelling…{:else}Cancel recovery{/if}
  </button>
  <p class="hint" id="cancel-result">
    {#if wasCancelled}The recovery was cancelled.{:else}{step.errorMessage}{/if}
  </p>
{:else}
  <Marmot pose="lost" />
  <h1>This link is incomplete</h1>
  <p class="subtitle">Open the link from the email again.</p>
{/if}
