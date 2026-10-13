<script>
  // The two ways to protect an account, side by side. The ids are used by the browser tests.

  let { wantsEscrow = $bindable(false) } = $props()
</script>

<div class="choice-grid">
  <label class="choice-card" for="escrow-none">
    <span class="choice-title">
      <input type="radio" name="escrow" id="escrow-none" checked={!wantsEscrow} onchange={() => (wantsEscrow = false)} />
      Only you can unlock (recommended)
    </span>

    <span class="choice-heading choice-pros">Advantages</span>
    <ul class="choice-list choice-pros">
      <li>Nobody can read it, not even us.</li>
      <li>There is no key for anyone to steal or be forced to hand over.</li>
    </ul>

    <span class="choice-heading choice-cons">Disadvantages</span>
    <ul class="choice-list choice-cons">
      <li>If you forget your password and lose your recovery key, your data is gone.</li>
      <li>We cannot help you get back in.</li>
    </ul>
  </label>

  <label class="choice-card" for="escrow-help">
    <span class="choice-title">
      <input type="radio" name="escrow" id="escrow-help" checked={wantsEscrow} onchange={() => (wantsEscrow = true)} />
      Neoworks can help you recover
    </span>

    <span class="choice-heading choice-pros">Advantages</span>
    <ul class="choice-list choice-pros">
      <li>We can restore your access after verifying your email and a waiting period.</li>
      <li>A safety net if you lose both your password and your recovery key.</li>
      <li>You are told about every recovery and can cancel it.</li>
    </ul>

    <span class="choice-heading choice-cons">Disadvantages</span>
    <ul class="choice-list choice-cons">
      <li>We, or anyone who breaks into or legally compels us, could decrypt your data.</li>
      <li>Recovery is delayed by a waiting period.</li>
    </ul>
  </label>
</div>
