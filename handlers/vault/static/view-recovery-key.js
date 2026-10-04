// Shows a recovery key once and requires the user to confirm they saved it.

import { describeError } from "./nw-api.js";
import { errorBox, h, withBusy } from "./nw-dom.js";
import { heading, mountView } from "./nw-layout.js";
import { downloadRecoveryKey } from "./nw-recovery.js";

function wordList(words) {
  return h("div", { class: "recovery-box recovery-words", id: "recovery-words" },
    words.map((word, position) => h("div", null, h("span", { class: "word-index" }, (position + 1) + "."), word)));
}

function extraRows(extras) {
  if (extras === undefined) {
    return [];
  }
  return extras;
}

// renderRecoveryKeyConfirmation shows the words. onConfirm runs after the user
// ticks the confirmation and presses the button; extras are extra form rows.
export function renderRecoveryKeyConfirmation(context, { words, confirmLabel, onConfirm, extras }) {
  const confirmBox = h("input", { type: "checkbox", id: "recovery-confirm" });
  const failure = errorBox();
  const proceed = h("button", { type: "button", id: "confirm-recovery", disabled: true }, confirmLabel);
  confirmBox.addEventListener("change", () => {
    proceed.disabled = !confirmBox.checked;
  });
  proceed.addEventListener("click", () => withBusy(proceed, "Working…", async () => {
    failure.clear();
    try {
      await onConfirm();
    } catch (error) {
      failure.show(describeError(error));
    }
  }));
  mountView(context,
    ...heading("Save your recovery key", "This key is the only way back into your account if you forget your password. We cannot show it again."),
    wordList(words),
    h("div", { class: "recovery-actions" },
      h("button", { type: "button", class: "copy-btn", onclick: () => navigator.clipboard.writeText(words.join(" ")) }, "Copy"),
      h("button", { type: "button", class: "copy-btn", onclick: () => downloadRecoveryKey(words) }, "Download")),
    failure.element,
    h("div", { class: "checkbox-row" }, confirmBox, h("label", { for: "recovery-confirm" }, "I saved my recovery key in a safe place")),
    ...extraRows(extras),
    proceed);
}
