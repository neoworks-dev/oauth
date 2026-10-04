// Forgot password: prove the email, then unwrap the AMK with the recovery key
// and set a new password.

import { derivePasswordKeys, deriveRecoveryKek, newPwhashParams, unwrapAmk, unwrapIdentity, wrapAmk } from "./nw-account.js";
import { describeError, postJson } from "./nw-api.js";
import { errorBox, field, h, withBusy } from "./nw-dom.js";
import { heading, link, mountView } from "./nw-layout.js";
import { parseRecoveryWords } from "./nw-recovery.js";
import { decodeBase64Url, encodeBase64Url, wipe } from "./nw-primitives.js";
import { renderEscrowRecovery } from "./view-recover-escrow.js";

const MIN_PASSWORD_LENGTH = 8;

export function renderRecover(context) {
  const email = field("Email", { id: "email", type: "email", autocomplete: "email", required: true, autofocus: true });
  const failure = errorBox();
  const submit = h("button", { type: "submit" }, "Send code");
  const form = h("form", {
    onsubmit: async (event) => {
      event.preventDefault();
      failure.clear();
      await withBusy(submit, "Sending…", async () => {
        try {
          const sent = await postJson("/vault/forgot/send-code", { email: email.input.value.trim() });
          renderCodeStep(context, email.input.value.trim(), sent.code);
        } catch (error) {
          failure.show(describeError(error));
        }
      });
    },
  }, failure.element, email.row, submit);
  mountView(context, ...heading("Reset your password", "We will email you a code. You will also need your recovery key."),
    form, h("p", { class: "signin-link" }, link("Back to sign in", "/signin" + context.challengeQuery, context.navigate)));
}

function renderCodeStep(context, email, debugCode) {
  const code = field("Verification code", { id: "code", inputmode: "numeric", autocomplete: "one-time-code", required: true, autofocus: true });
  const failure = errorBox();
  const submit = h("button", { type: "submit" }, "Verify");
  const form = h("form", {
    onsubmit: async (event) => {
      event.preventDefault();
      failure.clear();
      await withBusy(submit, "Verifying…", async () => {
        try {
          const released = await postJson("/vault/forgot/verify-code", { email, code: code.input.value.trim() });
          renderMethodStep(context, email, released);
        } catch (error) {
          failure.show(describeError(error));
        }
      });
    },
  }, failure.element, code.row, submit);
  const hint = h("p", { class: "hint", id: "debug-code" });
  if (debugCode) {
    hint.textContent = "Development code: " + debugCode;
  }
  mountView(context, ...heading("Check your email", "Enter the 6-digit code sent to " + email + "."), form, hint);
}

function renderMethodStep(context, email, released) {
  const words = h("textarea", { id: "recovery-words-input", rows: 4, placeholder: "Enter your recovery key words", required: true });
  const failure = errorBox();
  const submit = h("button", { type: "submit" }, "Continue");
  const form = h("form", {
    onsubmit: async (event) => {
      event.preventDefault();
      failure.clear();
      await withBusy(submit, "Checking…", async () => {
        try {
          const amk = openWithRecoveryKey(released, words.value);
          renderNewPasswordStep(context, released, amk);
        } catch (error) {
          failure.show("That recovery key does not match this account.");
        }
      });
    },
  }, failure.element, h("div", { class: "field" }, h("label", { for: "recovery-words-input" }, "Recovery key"), words), submit);
  const parts = [...heading("Use your recovery key", "Enter the words you saved when you created your account."), form];
  if (released.escrowEnabled && context.boot.escrowAvailable) {
    parts.push(h("div", { class: "divider" }, "or"), renderEscrowRecovery(context, email, released));
  }
  mountView(context, ...parts);
}

// openWithRecoveryKey unwraps the AMK and checks it opens the identity.
function openWithRecoveryKey(released, wordsText) {
  const entropy = parseRecoveryWords(wordsText);
  const bundle = released.bundle;
  const amk = unwrapAmk(deriveRecoveryKek(entropy), decodeBase64Url(bundle.amkRecovery), bundle.userId, "recovery");
  unwrapIdentity(amk, bundle);
  wipe(entropy);
  return amk;
}

export function renderNewPasswordStep(context, released, amk) {
  const password = field("New password", { id: "new-password", type: "password", autocomplete: "new-password", required: true, autofocus: true });
  const failure = errorBox();
  const submit = h("button", { type: "submit" }, "Set password");
  const form = h("form", {
    onsubmit: async (event) => {
      event.preventDefault();
      failure.clear();
      if (password.input.value.length < MIN_PASSWORD_LENGTH) {
        failure.show("Password must be at least " + MIN_PASSWORD_LENGTH + " characters.");
        return;
      }
      await withBusy(submit, "Saving…", async () => {
        try {
          await resetPassword(released, amk, password.input.value);
          context.navigate("/signin" + context.challengeQuery);
        } catch (error) {
          failure.show(describeError(error));
        }
      });
    },
  }, failure.element, password.row, submit);
  mountView(context, ...heading("Choose a new password", "Your data stays encrypted with the same key."), form);
}

async function resetPassword(released, amk, newPassword) {
  const pwhash = newPwhashParams();
  const keys = derivePasswordKeys(newPassword, pwhash);
  const amkPassword = encodeBase64Url(wrapAmk(keys.passwordKEK, amk, released.bundle.userId, "password"));
  await postJson("/vault/forgot/reset", {
    resetToken: released.resetToken, newAuthKey: encodeBase64Url(keys.authKey), pwhash, amkPassword,
    expectedVersion: released.bundle.version,
  });
  wipe(keys.authKey);
  wipe(keys.passwordKEK);
  wipe(amk);
}
