import { showComponent } from "./mountView.js"
import RecoveryKey from "./RecoveryKey.svelte"

// Shows the recovery words once. onConfirm runs after the user confirms they saved them;
// extras are extra DOM rows (such as a "remember this browser" checkbox) shown above the button.
export function renderRecoveryKeyConfirmation(context, { words, confirmLabel, onConfirm, extras = [] }) {
  showComponent(context, RecoveryKey, { words, confirmLabel, onConfirm, extras })
}
