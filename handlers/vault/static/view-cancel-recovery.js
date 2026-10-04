// The page behind the cancel link in the recovery notification email. The
// attempt id and token travel in the URL fragment so they never reach logs.

import { describeError, postJson } from "./nw-api.js";
import { h, withBusy } from "./nw-dom.js";
import { heading, mountView } from "./nw-layout.js";

export function renderCancelRecovery(context) {
  const fragment = new URLSearchParams(location.hash.slice(1));
  const attemptId = fragment.get("a");
  const token = fragment.get("t");
  if (attemptId === null || token === null) {
    mountView(context, ...heading("This link is incomplete", "Open the link from the email again."));
    return;
  }
  const result = h("p", { class: "hint", id: "cancel-result" });
  const button = h("button", { type: "button", id: "cancel-recovery" }, "Cancel recovery");
  button.addEventListener("click", () => withBusy(button, "Cancelling…", async () => {
    try {
      await postJson("/vault/escrow/recovery/cancel", { attemptId, token });
      result.textContent = "The recovery was cancelled.";
    } catch (error) {
      result.textContent = describeError(error);
    }
  }));
  mountView(context,
    ...heading("Cancel account recovery", "Someone asked Neoworks to restore access to your account. If this was not you, cancel it."),
    button, result);
}
