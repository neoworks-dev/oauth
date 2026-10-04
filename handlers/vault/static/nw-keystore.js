// Holds the unlocked account state. The plaintext AMK and identity secrets live
// only in this module's memory. A browser device wrap (the AMK encrypted by a
// non-extractable AES-GCM key in IndexedDB) lets this browser unlock without
// the password when the user chose to remember it.

import { unwrapIdentity } from "./nw-account.js";
import { openPreviousIdentity } from "./nw-rotation.js";
import { unwrapWithBrowserKey, wrapWithBrowserKey } from "./nw-browser-wrap.js";
import { META_STORE, WRAP_STORE, deleteRecord, readRecord, writeRecord } from "./nw-idb.js";
import { wipe } from "./nw-primitives.js";

const IDLE_LOCK_MS = 15 * 60 * 1000;

let unlocked = null;
let idleTimer = null;
let onLock = null;

export function isUnlocked() {
  return unlocked !== null;
}

export function currentUserId() {
  if (unlocked === null) {
    return null;
  }
  return unlocked.userId;
}

export function requireUnlocked() {
  if (unlocked === null) {
    throw new Error("vault is locked");
  }
  return unlocked;
}

// unlock verifies the AMK by opening the identity and then keeps both.
export function unlock(amk, bundle) {
  const identity = unwrapIdentity(amk, bundle);
  const previousIdentity = openPreviousIdentity(amk, bundle);
  discardCurrent(amk);
  unlocked = { userId: bundle.userId, amk, identity, previousIdentity, bundle };
  armIdleTimer();
}

function discardCurrent(keptAmk) {
  if (unlocked === null) {
    return;
  }
  if (unlocked.amk !== keptAmk) {
    wipe(unlocked.amk);
  }
  wipe(unlocked.identity.encSec);
  wipe(unlocked.identity.signSec);
  if (unlocked.previousIdentity !== null) {
    wipe(unlocked.previousIdentity.encSec);
    wipe(unlocked.previousIdentity.signSec);
  }
  unlocked = null;
}

export function lock() {
  discardCurrent(null);
  clearTimeout(idleTimer);
}

export function setLockListener(listener) {
  onLock = listener;
}

function armIdleTimer() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(idleLock, IDLE_LOCK_MS);
}

function idleLock() {
  lock();
  if (onLock) {
    onLock();
  }
}

export function noteActivity() {
  if (unlocked !== null) {
    armIdleTimer();
  }
}

// ── Browser device wrap ──────────────────────────────────────────────────────

const DEVICE_ID_KEY = "deviceId";

// getDeviceId returns this browser's stable device id, creating it on first use.
export async function getDeviceId() {
  const existing = await readRecord(META_STORE, DEVICE_ID_KEY);
  if (existing) {
    return existing;
  }
  const created = crypto.randomUUID();
  await writeRecord(META_STORE, created, DEVICE_ID_KEY);
  return created;
}

function deviceWrapAad(userId) {
  return "nw-device-wrap-v1:" + userId;
}

export async function saveDeviceWrap(userId, amk) {
  const wrapped = await wrapWithBrowserKey(amk, deviceWrapAad(userId));
  await writeRecord(WRAP_STORE, { userId, ...wrapped });
}

export async function hasDeviceWrap(userId) {
  const record = await readRecord(WRAP_STORE, userId);
  return record !== undefined;
}

// loadDeviceWrap returns the AMK for this browser, or null when there is no wrap
// or it can no longer be opened.
export async function loadDeviceWrap(userId) {
  const record = await readRecord(WRAP_STORE, userId);
  if (!record) {
    return null;
  }
  return unwrapWithBrowserKey(record, deviceWrapAad(userId));
}

export async function clearDeviceWrap(userId) {
  await deleteRecord(WRAP_STORE, userId);
}
