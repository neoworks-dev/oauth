// Session and unlock flow shared by every signed-in view.

import { getJson } from "./nw-api.js";
import { currentUserId, hasDeviceWrap, isUnlocked, loadDeviceWrap, unlock } from "./nw-keystore.js";
import { renderLogin } from "./view-login.js";
import { renderUnlock } from "./view-unlock.js";

// tryDeviceUnlock opens the keystore from this browser's device wrap.
export async function tryDeviceUnlock(session) {
  const amk = await loadDeviceWrap(session.userId);
  if (amk === null) {
    return false;
  }
  try {
    unlock(amk, await getJson("/vault/bundle"));
    return true;
  } catch (error) {
    return false;
  }
}

// ensureAccess makes sure there is a signed-in, unlocked account and then calls
// onReady with the session. It renders login or unlock as needed.
export async function ensureAccess(context, onReady) {
  const session = await getJson("/vault/session");
  context.session = session;
  if (!session.authenticated) {
    renderLogin(context, { onDone: () => ensureAccess(context, onReady) });
    return;
  }
  if (isUnlocked() && currentUserId() === session.userId) {
    onReady(session);
    return;
  }
  if (!context.lockedByIdle && await tryDeviceUnlock(session)) {
    onReady(session);
    return;
  }
  const remembered = await hasDeviceWrap(session.userId);
  renderUnlock(context, { session, remembered, onDone: () => ensureAccess(context, onReady) });
}
