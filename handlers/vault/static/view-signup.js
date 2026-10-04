// Signup: account details, email check, escrow choice and the recovery key.
// Every key is created here in the browser.

import { describeError, getJson, postJson } from "./nw-api.js";
import { describeBrowser } from "./nw-browser.js";
import { errorBox, field, h, withBusy } from "./nw-dom.js";
import { ESCROW_PUBLIC_KEY } from "./escrow-key.js";
import { getDeviceId, saveDeviceWrap, unlock } from "./nw-keystore.js";
import { heading, link, mountView } from "./nw-layout.js";
import { createSignupMaterial } from "./nw-signup-material.js";
import { renderRecoveryKeyConfirmation } from "./view-recovery-key.js";

const MIN_PASSWORD_LENGTH = 8;

function escrowOffered(context) {
  return context.boot.escrowAvailable && ESCROW_PUBLIC_KEY !== null;
}

export function renderSignup(context, { onDone }) {
  const details = { email: "", firstName: "", lastName: "", password: "" };
  renderAccountStep(context, details, onDone);
}

function subtitleFor(context) {
  if (context.challenge) {
    return "Sign up to continue to " + context.challenge.clientName;
  }
  return "Get started with Neoworks";
}

function renderAccountStep(context, details, onDone) {
  const firstName = field("First name", { id: "first-name", autocomplete: "given-name", required: true, autofocus: true });
  const lastName = field("Last name", { id: "last-name", autocomplete: "family-name", required: true });
  const email = field("Email", { id: "email", type: "email", autocomplete: "email", required: true });
  const password = field("Password", { id: "password", type: "password", autocomplete: "new-password", required: true });
  const failure = errorBox();
  const submit = h("button", { type: "submit" }, "Continue");

  const form = h("form", {
    onsubmit: async (event) => {
      event.preventDefault();
      failure.clear();
      Object.assign(details, {
        firstName: firstName.input.value.trim(), lastName: lastName.input.value.trim(),
        email: email.input.value.trim(), password: password.input.value,
      });
      await withBusy(submit, "Sending code…", () => requestCode(context, details, failure, onDone));
    },
  }, failure.element, h("div", { class: "row" }, firstName.row, lastName.row), email.row, password.row, submit);

  mountView(context, ...heading("Create account", subtitleFor(context)), form,
    h("p", { class: "signin-link" }, "Already have an account? ", link("Sign in", "/signin" + context.challengeQuery, context.navigate)));
}

async function requestCode(context, details, failure, onDone) {
  if (details.password.length < MIN_PASSWORD_LENGTH) {
    failure.show("Password must be at least " + MIN_PASSWORD_LENGTH + " characters.");
    return;
  }
  try {
    const sent = await postJson("/vault/signup/send-code", { email: details.email });
    renderCodeStep(context, details, sent.code, onDone);
  } catch (error) {
    failure.show(describeError(error));
  }
}

function renderCodeStep(context, details, debugCode, onDone) {
  const code = field("Verification code", { id: "code", inputmode: "numeric", autocomplete: "one-time-code", required: true, autofocus: true });
  const failure = errorBox();
  const submit = h("button", { type: "submit" }, "Verify email");
  const form = h("form", {
    onsubmit: async (event) => {
      event.preventDefault();
      failure.clear();
      await withBusy(submit, "Verifying…", async () => {
        try {
          await postJson("/vault/signup/verify-code", { email: details.email, code: code.input.value.trim() });
          renderEscrowStep(context, details, onDone);
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
  mountView(context, ...heading("Verify your email", "We sent a 6-digit code to " + details.email + "."), form, hint);
}

function escrowOption(id, title, text, checked) {
  const input = h("input", { type: "radio", name: "escrow", id, checked });
  const label = h("label", { for: id, class: "choice" }, h("strong", null, title), h("span", { class: "hint" }, text));
  return { input, row: h("div", { class: "checkbox-row choice-row" }, input, label) };
}

function renderEscrowStep(context, details, onDone) {
  if (!escrowOffered(context)) {
    startRecoveryStep(context, details, false, onDone);
    return;
  }
  const keep = escrowOption("escrow-none", "Only you can unlock (recommended)",
    "If you forget your password and lose your recovery key, your data is gone. Nobody can read it, not even us.", true);
  const help = escrowOption("escrow-help", "Neoworks can help you recover",
    "We can restore your access after verifying your email and a waiting period. The trade-off: we, or anyone who breaks into or legally compels us, could decrypt your data.", false);
  const next = h("button", { type: "button", id: "escrow-continue", onclick: () => startRecoveryStep(context, details, help.input.checked, onDone) }, "Continue");
  mountView(context, ...heading("Protect your account", "Choose what happens if you lose access. You can change this later in settings."),
    keep.row, help.row, next);
}

async function startRecoveryStep(context, details, escrowEnabled, onDone) {
  mountView(context, ...heading("Creating your keys…", "Your keys are generated in this browser."));
  await new Promise((resolve) => setTimeout(resolve, 50));
  let escrowPublicKey = null;
  if (escrowEnabled) {
    escrowPublicKey = ESCROW_PUBLIC_KEY;
  }
  const material = createSignupMaterial({
    email: details.email, firstName: details.firstName, lastName: details.lastName, password: details.password,
    deviceId: await getDeviceId(), deviceName: describeBrowser(), escrowPublicKey,
  });
  details.password = "";
  renderRecoveryKeyStep(context, material, onDone);
}

function renderRecoveryKeyStep(context, material, onDone) {
  const remember = h("input", { type: "checkbox", id: "remember", checked: true });
  renderRecoveryKeyConfirmation(context, {
    words: material.recoveryWords,
    confirmLabel: "Create account",
    extras: [h("div", { class: "checkbox-row" }, remember, h("label", { for: "remember" }, "Remember this browser"))],
    onConfirm: () => submitSignup(material, remember.checked, onDone),
  });
}

async function submitSignup(material, remember, onDone) {
  await postJson("/vault/signup", material.request);
  const bundle = await getJson("/vault/bundle");
  unlock(material.amk, bundle);
  if (remember) {
    await saveDeviceWrap(material.userId, material.amk);
  }
  onDone();
}
