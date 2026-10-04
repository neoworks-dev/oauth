// Unlocking an existing session: password, this browser's device wrap, or the
// Neoworks Authenticator.

import { derivePasswordKeys, unwrapAmk } from "./nw-account.js";
import { describeError, getJson, postJson } from "./nw-api.js";
import { errorBox, field, h, withBusy } from "./nw-dom.js";
import { startHandover } from "./handover-client.js";
import { loadDeviceWrap, saveDeviceWrap, unlock } from "./nw-keystore.js";
import { heading, mountView } from "./nw-layout.js";
import { decodeBase64Url, wipe } from "./nw-primitives.js";

async function unlockWithPassword(session, password) {
  const bundle = await getJson("/vault/bundle");
  const keys = derivePasswordKeys(password, { salt: bundle.pwhashSalt, ops: bundle.pwhashOps, mem: bundle.pwhashMem });
  const amk = unwrapAmk(keys.passwordKEK, decodeBase64Url(bundle.amkPassword), session.userId, "password");
  wipe(keys.authKey);
  wipe(keys.passwordKEK);
  unlock(amk, bundle);
  return amk;
}

async function unlockWithDeviceWrap(session) {
  const amk = await loadDeviceWrap(session.userId);
  if (amk === null) {
    return false;
  }
  unlock(amk, await getJson("/vault/bundle"));
  return true;
}

function passwordForm(session, remembered, onDone) {
  const password = field("Password", { id: "password", type: "password", autocomplete: "current-password", required: true, autofocus: true });
  const remember = h("input", { type: "checkbox", id: "remember", checked: remembered });
  const failure = errorBox();
  const submit = h("button", { type: "submit" }, "Unlock");
  const form = h("form", {
    onsubmit: async (event) => {
      event.preventDefault();
      failure.clear();
      await withBusy(submit, "Unlocking…", async () => {
        try {
          const amk = await unlockWithPassword(session, password.input.value);
          if (remember.checked) {
            await saveDeviceWrap(session.userId, amk);
          }
          onDone();
        } catch (error) {
          failure.show("That password did not unlock your account.");
        }
      });
    },
  }, failure.element, password.row,
  h("div", { class: "checkbox-row" }, remember, h("label", { for: "remember" }, "Remember this browser")),
  submit);
  return form;
}

function deviceButton(session, onDone) {
  const failure = errorBox();
  const button = h("button", {
    type: "button",
    class: "secondary",
    id: "unlock-device",
    onclick: () => withBusy(button, "Unlocking…", async () => {
      try {
        await unlockWithDeviceWrap(session);
        onDone();
      } catch (error) {
        failure.show(describeError(error));
      }
    }),
  }, "Unlock with this browser");
  return h("div", null, failure.element, button);
}

function authenticatorPanel(context, session, onDone) {
  const container = h("div", { class: "handover" });
  const signal = { cancelled: false };
  context.cancelOnNavigate = () => {
    signal.cancelled = true;
  };
  const start = h("button", {
    type: "button",
    class: "secondary",
    id: "unlock-authenticator",
    onclick: async () => {
      start.hidden = true;
      const amk = await startHandover({ container, vaultOrigin: context.boot.vaultOrigin, expectedUserId: session.userId, signal });
      await finishHandover(container, session, amk, onDone);
    },
  }, "Unlock with the Neoworks Authenticator");
  return h("div", null, start, container);
}

async function finishHandover(container, session, amk, onDone) {
  if (amk === null) {
    container.replaceChildren(h("p", { class: "error" }, "The authenticator did not answer in time."));
    return;
  }
  try {
    unlock(amk, await getJson("/vault/bundle"));
    onDone();
  } catch (error) {
    container.replaceChildren(h("p", { class: "error" }, "The authenticator sent a key that does not match this account."));
  }
}

export function renderUnlock(context, { session, remembered, onDone }) {
  const parts = [...heading("Unlock your account", session.email), passwordForm(session, remembered, onDone)];
  if (remembered) {
    parts.push(h("div", { class: "divider" }, "or"), deviceButton(session, onDone));
  }
  parts.push(authenticatorPanel(context, session, onDone));
  parts.push(h("button", {
    type: "button",
    class: "ghost",
    id: "sign-out",
    onclick: async () => {
      await postJson("/vault/logout");
      context.lockedByIdle = false;
      onDone();
    },
  }, "Sign out"));
  mountView(context, ...parts);
}
