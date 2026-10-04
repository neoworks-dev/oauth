// Password login. The password is stretched in the browser; only authKey is sent.

import { derivePasswordKeys, unwrapAmk } from "./nw-account.js";
import { describeError, getJson, postJson } from "./nw-api.js";
import { describeBrowser } from "./nw-browser.js";
import { errorBox, field, h, withBusy } from "./nw-dom.js";
import { getDeviceId, saveDeviceWrap, unlock } from "./nw-keystore.js";
import { heading, link, mountView } from "./nw-layout.js";
import { decodeBase64Url, encodeBase64Url, wipe } from "./nw-primitives.js";

// signInWithPassword runs prelogin and login, returns the session and the AMK.
export async function signInWithPassword(email, password) {
  const params = await postJson("/vault/prelogin", { email });
  const keys = derivePasswordKeys(password, params);
  const login = await postJson("/vault/login", {
    email,
    authKey: encodeBase64Url(keys.authKey),
    deviceId: await getDeviceId(),
    deviceName: describeBrowser(),
  });
  const amk = unwrapAmk(keys.passwordKEK, decodeBase64Url(login.bundle.amkPassword), login.userId, "password");
  wipe(keys.authKey);
  wipe(keys.passwordKEK);
  return { login, amk };
}

// finishSignIn unlocks the keystore and, if asked, remembers this browser.
export async function finishSignIn(login, amk, remember) {
  unlock(amk, login.bundle);
  if (remember) {
    await saveDeviceWrap(login.userId, amk);
  }
}

function subtitleFor(context) {
  if (context.challenge) {
    return "Sign in to continue to " + context.challenge.clientName;
  }
  return "Sign in to your account";
}

export function renderLogin(context, { onDone }) {
  const email = field("Email", { id: "email", type: "email", autocomplete: "username", required: true, autofocus: true });
  const password = field("Password", { id: "password", type: "password", autocomplete: "current-password", required: true });
  const remember = h("input", { type: "checkbox", id: "remember", checked: true });
  const failure = errorBox();
  const submit = h("button", { type: "submit" }, "Sign in");

  const form = h("form", {
    onsubmit: async (event) => {
      event.preventDefault();
      failure.clear();
      await withBusy(submit, "Signing in…", async () => {
        try {
          const { login, amk } = await signInWithPassword(email.input.value.trim(), password.input.value);
          await finishSignIn(login, amk, remember.checked);
          onDone();
        } catch (error) {
          failure.show(describeError(error));
        }
      });
    },
  },
  failure.element, email.row, password.row,
  h("div", { class: "checkbox-row" }, remember, h("label", { for: "remember" }, "Remember this browser")),
  submit);

  mountView(context,
    ...heading("Sign in", subtitleFor(context)),
    form,
    h("p", { class: "signin-link" }, link("Forgot your password?", "/recover", context.navigate)),
    h("p", { class: "signin-link" }, "New to Neoworks? ", link("Create an account", signupHref(context), context.navigate)));
}

function signupHref(context) {
  if (context.challengeId) {
    return "/signup?login_challenge=" + encodeURIComponent(context.challengeId);
  }
  return "/signup";
}

export { getJson };
