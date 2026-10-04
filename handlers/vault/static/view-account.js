// The signed-in account page: this browser, password, keys, recovery help.

import { changePassword, commitRotation, finishRotation, prepareFullRotation, prepareLightRotation } from "./account-actions.js";
import { describeError, getJson, postJson } from "./nw-api.js";
import { ESCROW_PUBLIC_KEY } from "./escrow-key.js";
import { errorBox, field, h, withBusy } from "./nw-dom.js";
import { clearDeviceWrap, hasDeviceWrap, lock, requireUnlocked, saveDeviceWrap } from "./nw-keystore.js";
import { heading, mountView } from "./nw-layout.js";
import { bytesToWords } from "./nw-recovery.js";
import { renderEscrowSettings } from "./view-escrow-settings.js";
import { renderRecoveryKeyConfirmation } from "./view-recovery-key.js";

const MIN_PASSWORD_LENGTH = 8;

function section(title, ...children) {
  return h("section", { class: "account-section" }, h("h2", null, title), ...children);
}

function paintBrowserStatus(status, toggle, isRemembered) {
  if (isRemembered) {
    status.textContent = "This browser unlocks your account without a password.";
    toggle.textContent = "Forget this browser";
  } else {
    status.textContent = "This browser asks for your password.";
    toggle.textContent = "Remember this browser";
  }
  toggle.dataset.remembered = String(isRemembered);
}

async function browserSection(session) {
  const remembered = await hasDeviceWrap(session.userId);
  const status = h("p", { class: "hint", id: "browser-status" });
  const toggle = h("button", { type: "button", class: "secondary", id: "toggle-remember" });
  const paint = (isRemembered) => {
    paintBrowserStatus(status, toggle, isRemembered);
  };
  paint(remembered);
  toggle.addEventListener("click", async () => {
    if (toggle.dataset.remembered === "true") {
      await clearDeviceWrap(session.userId);
      paint(false);
      return;
    }
    await saveDeviceWrap(session.userId, requireUnlocked().amk);
    paint(true);
  });
  return section("This browser", status, toggle);
}

function passwordSection() {
  const current = field("Current password", { id: "current-password", type: "password", autocomplete: "current-password", required: true });
  const next = field("New password", { id: "new-password", type: "password", autocomplete: "new-password", required: true });
  const failure = errorBox();
  const done = h("p", { class: "success", id: "password-changed", hidden: true }, "Password changed.");
  const submit = h("button", { type: "submit" }, "Change password");
  const form = h("form", {
    onsubmit: async (event) => {
      event.preventDefault();
      failure.clear();
      done.hidden = true;
      if (next.input.value.length < MIN_PASSWORD_LENGTH) {
        failure.show("Password must be at least " + MIN_PASSWORD_LENGTH + " characters.");
        return;
      }
      await withBusy(submit, "Changing…", async () => {
        try {
          await changePassword(current.input.value, next.input.value);
          form.reset();
          done.hidden = false;
        } catch (error) {
          failure.show(describeError(error));
        }
      });
    },
  }, failure.element, current.row, next.row, submit, done);
  return section("Password", form);
}

function rotationSection(context, session) {
  const password = field("Your password", { id: "rotate-password", type: "password", autocomplete: "current-password", required: true });
  const failure = errorBox();
  const submit = h("button", { type: "submit", class: "secondary" }, "Create new keys");
  const form = h("form", {
    onsubmit: async (event) => {
      event.preventDefault();
      failure.clear();
      await withBusy(submit, "Preparing…", async () => {
        try {
          await startRotation(context, session, password.input.value);
        } catch (error) {
          failure.show("That password did not match your account.");
        }
      });
    },
  }, failure.element, password.row, submit);
  return section("Replace account key",
    h("p", { class: "hint" },
      "Creates a new account master key and a new recovery key. Your data is not re-encrypted. Use this if a device that held your key may have been exposed but was probably locked. Data written before a stronger rotation stays readable to anyone who already copied the old key."),
    form);
}

function identitySection(context, session) {
  const password = field("Your password", { id: "identity-password", type: "password", autocomplete: "current-password", required: true });
  const failure = errorBox();
  const submit = h("button", { type: "submit", class: "secondary", id: "replace-identity" }, "Replace identity keys");
  const form = h("form", {
    onsubmit: async (event) => {
      event.preventDefault();
      failure.clear();
      await withBusy(submit, "Preparing…", async () => {
        try {
          await startIdentityRotation(context, session, password.input.value);
        } catch (error) {
          failure.show(describeError(error));
        }
      });
    },
  }, failure.element, password.row, submit);
  return section("Replace identity keys",
    h("p", { class: "hint" },
      "Creates a new identity and a new account master key, then seals your own data keys to the new identity. " +
      "The old identity stays in your account until that is finished, so an interruption loses nothing. " +
      "People who shared something with you need to share it again afterwards."),
    form);
}

function finishSection(context) {
  const password = field("Your password", { id: "finish-password", type: "password", autocomplete: "current-password", required: true });
  const failure = errorBox();
  const submit = h("button", { type: "submit", id: "finish-rotation" }, "Finish key replacement");
  const form = h("form", {
    onsubmit: async (event) => {
      event.preventDefault();
      failure.clear();
      await withBusy(submit, "Finishing…", async () => {
        try {
          await finishRotation(context.boot.apiUrl, password.input.value);
          context.navigate("/account");
        } catch (error) {
          failure.show(describeError(error));
        }
      });
    },
  }, failure.element, password.row, submit);
  return section("Finish key replacement",
    h("p", { class: "hint" }, "A key replacement was started but not finished. Your old identity is still kept so nothing is lost."),
    form);
}

async function startIdentityRotation(context, session, password) {
  const bundle = await getJson("/vault/bundle");
  const prepared = prepareFullRotation(bundle, password, rotationEscrow(session));
  renderRecoveryKeyConfirmation(context, {
    words: bytesToWords(prepared.recoveryEntropy),
    confirmLabel: "Replace identity",
    onConfirm: async () => {
      await commitRotation(prepared);
      await finishRotation(context.boot.apiUrl, password);
      context.navigate("/account");
    },
  });
}

function rotationEscrow(session) {
  if (session.escrowEnabled) {
    return { mode: "replace", publicKey: ESCROW_PUBLIC_KEY };
  }
  return { mode: "none" };
}

async function startRotation(context, session, password) {
  const bundle = await getJson("/vault/bundle");
  const prepared = prepareLightRotation(bundle, password, rotationEscrow(session));
  renderRecoveryKeyConfirmation(context, {
    words: bytesToWords(prepared.recoveryEntropy),
    confirmLabel: "Replace key",
    onConfirm: async () => {
      await commitRotation(prepared);
      context.navigate("/account");
    },
  });
}

function signOutSection(context) {
  return section("Session", h("button", {
    type: "button",
    class: "ghost",
    id: "sign-out",
    onclick: async () => {
      await postJson("/vault/logout");
      lock();
      context.navigate("/signin");
    },
  }, "Sign out"));
}

export async function renderAccount(context, session) {
  const parts = [
    ...heading("Your account", session.email),
    await browserSection(session), passwordSection(), rotationSection(context, session),
  ];
  if (requireUnlocked().previousIdentity !== null) {
    parts.push(finishSection(context));
  }
  parts.push(identitySection(context, session));
  if (context.boot.escrowAvailable) {
    parts.push(renderEscrowSettings(context, session));
  }
  parts.push(signOutSection(context));
  mountView(context, ...parts);
}
