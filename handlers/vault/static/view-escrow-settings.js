// Settings for opt-in recovery help (escrow): turn it on or off, and see or
// cancel a recovery someone started.

import { commitRotation, enableEscrow, finishRotation, prepareFullRotation } from "./account-actions.js";
import { describeError, getJson, postJson } from "./nw-api.js";
import { ESCROW_PUBLIC_KEY } from "./escrow-key.js";
import { errorBox, field, h, withBusy } from "./nw-dom.js";
import { bytesToWords } from "./nw-recovery.js";
import { renderRecoveryKeyConfirmation } from "./view-recovery-key.js";

const TRADE_OFF = "The trade-off: we, or anyone who breaks into or legally compels us, could decrypt your data.";
const DISABLE_NOTE = "Turning this off replaces your account key and identity keys, creates a new recovery key and deletes our copy. " +
  "Your own data keys are sealed to the new identity. People who shared something with you need to share it again afterwards. " +
  "Anyone who already copied the old key can still read data written before this.";

function passwordForm(label, onSubmit) {
  const password = field("Your password", { id: "escrow-password", type: "password", autocomplete: "current-password", required: true });
  const failure = errorBox();
  const submit = h("button", { type: "submit", class: "secondary" }, label);
  const form = h("form", {
    onsubmit: async (event) => {
      event.preventDefault();
      failure.clear();
      await withBusy(submit, "Working…", async () => {
        try {
          await onSubmit(password.input.value);
        } catch (error) {
          failure.show(describeError(error));
        }
      });
    },
  }, failure.element, password.row, submit);
  return form;
}

function recoveryNotice(recovery, repaint) {
  const cancel = h("button", { type: "button", id: "cancel-" + recovery.id }, "Cancel recovery");
  cancel.addEventListener("click", async () => {
    await postJson("/vault/escrow/recoveries/" + recovery.id + "/cancel");
    repaint();
  });
  return h("div", { class: "notice", id: "pending-recovery" },
    h("p", { class: "error" }, "A recovery was started for this account. Access would be restored on " +
      new Date(recovery.readyAt).toLocaleString() + ". If this was not you, cancel it."),
    cancel);
}

function enabledPanel(context) {
  const form = passwordForm("Turn off recovery help", async (password) => {
    const bundle = await getJson("/vault/bundle");
    const prepared = prepareFullRotation(bundle, password, { mode: "disable" });
    renderRecoveryKeyConfirmation(context, {
      words: bytesToWords(prepared.recoveryEntropy),
      confirmLabel: "Replace keys and turn off",
      onConfirm: async () => {
        await commitRotation(prepared);
        await finishRotation(context.boot.apiUrl, password);
        context.navigate("/account");
      },
    });
  });
  return h("div", null,
    h("p", { class: "hint" }, "Neoworks can help you recover your account after verifying your email and a waiting period. " + TRADE_OFF),
    h("p", { class: "hint" }, DISABLE_NOTE), form);
}

function disabledPanel(repaint) {
  const form = passwordForm("Let Neoworks help me recover", async (password) => {
    await enableEscrow(password, ESCROW_PUBLIC_KEY);
    repaint();
  });
  return h("div", null,
    h("p", { class: "hint" }, "Only you can unlock your account. If you forget your password and lose your recovery key, your data is gone."),
    h("p", { class: "hint" }, "You can let Neoworks restore your access after verifying your email and a waiting period. " + TRADE_OFF),
    form);
}

export function renderEscrowSettings(context, session) {
  const body = h("div", { id: "escrow-body" });
  const section = h("section", { class: "account-section", id: "escrow-settings" }, h("h2", null, "Recovery help"), body);
  const repaint = async () => {
    const status = await getJson("/vault/escrow/status");
    const parts = status.recoveries.map((recovery) => recoveryNotice(recovery, repaint));
    if (status.enabled) {
      parts.push(enabledPanel(context));
    } else {
      parts.push(disabledPanel(repaint));
    }
    body.replaceChildren(...parts);
    session.escrowEnabled = status.enabled;
  };
  repaint();
  return section;
}
