// Password sign-in. The password is stretched in the browser; only authKey is sent.

import { derivePasswordKeys, unwrapAmk } from "$legacy/nw-account.js"
import { postJson } from "$legacy/nw-api.js"
import { describeBrowser } from "$legacy/nw-browser.js"
import { getDeviceId, saveDeviceWrap, unlock } from "$legacy/nw-keystore.js"
import { decodeBase64Url, encodeBase64Url, wipe } from "$legacy/nw-primitives.js"

// Runs prelogin and login. Returns the login response and the unwrapped account key.
export async function signInWithPassword(email, password) {
  const passwordParameters = await postJson("/vault/prelogin", { email })
  const keys = derivePasswordKeys(password, passwordParameters)
  const login = await postJson("/vault/login", {
    email,
    authKey: encodeBase64Url(keys.authKey),
    deviceId: await getDeviceId(),
    deviceName: describeBrowser(),
  })
  const accountKey = unwrapAmk(keys.passwordKEK, decodeBase64Url(login.bundle.amkPassword), login.userId, "password")
  wipe(keys.authKey)
  wipe(keys.passwordKEK)
  return { login, accountKey }
}

// Unlocks the keystore and, when asked, remembers this browser.
export async function finishSignIn(login, accountKey, rememberBrowser) {
  unlock(accountKey, login.bundle)
  if (rememberBrowser) {
    await saveDeviceWrap(login.userId, accountKey)
  }
}
