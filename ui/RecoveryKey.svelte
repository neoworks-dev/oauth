<script>
  // Shows a recovery key once and requires the user to confirm they saved it.

  import { downloadRecoveryKey } from "$legacy/nw-recovery.js"
  import Marmot from "./Marmot.svelte"
  import { createStepRunner } from "./stepRunner.svelte.js"

  let { words, confirmLabel, onConfirm, extras } = $props()

  const step = createStepRunner()
  let hasSavedKey = $state(false)

  // Callers outside Svelte pass their extra rows as ready-made DOM nodes.
  function appendNodes(container, nodes) {
    container.append(...nodes)
  }
</script>

<Marmot pose="locked" />
<h1>Save your recovery key</h1>
<p class="subtitle">
  This key is the only way back into your account if you forget your password. We cannot show it again.
</p>

<div class="recovery-box recovery-words" id="recovery-words">
  {#each words as word, position}
    <div><span class="word-index">{position + 1}.</span>{word}</div>
  {/each}
</div>

<div class="recovery-actions">
  <button type="button" class="copy-btn" onclick={() => navigator.clipboard.writeText(words.join(" "))}>Copy</button>
  <button type="button" class="copy-btn" onclick={() => downloadRecoveryKey(words)}>Download</button>
</div>

{#if step.errorMessage}<p class="error" role="alert">{step.errorMessage}</p>{/if}

<div class="checkbox-row">
  <input type="checkbox" id="recovery-confirm" bind:checked={hasSavedKey} />
  <label for="recovery-confirm">I saved my recovery key in a safe place</label>
</div>

<div use:appendNodes={extras}></div>

<button
  type="button"
  id="confirm-recovery"
  disabled={!hasSavedKey || step.isBusy}
  onclick={() => step.run(onConfirm)}
>
  {#if step.isBusy}Working…{:else}{confirmLabel}{/if}
</button>
