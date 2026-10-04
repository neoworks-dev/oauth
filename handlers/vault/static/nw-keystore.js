// Holds the unlocked account state. The plaintext AMK and identity secrets live
// only in this module's memory. A browser device wrap (the AMK encrypted by a
// non-extractable AES-GCM key in IndexedDB) lets this browser unlock without
// the password when the user chose to remember it.

import { unwrapIdentity } from "./nw-account.js";
import { randomBytes, utf8, wipe } from "./nw-primitives.js";

const DATABASE_NAME = "nw-vault";
const WRAP_STORE = "device-wraps";
const META_STORE = "meta";
const DEVICE_ID_KEY = "deviceId";
const IDLE_LOCK_MS = 15 * 60 * 1000;
const IV_BYTES = 12;

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
  discardCurrent(amk);
  unlocked = { userId: bundle.userId, amk, identity, bundle };
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

// ── IndexedDB ────────────────────────────────────────────────────────────────

function awaitRequest(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function openDatabase() {
  const opening = indexedDB.open(DATABASE_NAME, 1);
  opening.onupgradeneeded = () => {
    opening.result.createObjectStore(WRAP_STORE, { keyPath: "userId" });
    opening.result.createObjectStore(META_STORE);
  };
  return awaitRequest(opening);
}

async function readRecord(storeName, key) {
  const database = await openDatabase();
  const record = await awaitRequest(database.transaction(storeName).objectStore(storeName).get(key));
  database.close();
  return record;
}

async function writeRecord(storeName, record, key) {
  const database = await openDatabase();
  const transaction = database.transaction(storeName, "readwrite");
  await awaitRequest(transaction.objectStore(storeName).put(record, key));
  database.close();
}

async function deleteRecord(storeName, key) {
  const database = await openDatabase();
  const transaction = database.transaction(storeName, "readwrite");
  await awaitRequest(transaction.objectStore(storeName).delete(key));
  database.close();
}

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
  return utf8("nw-device-wrap-v1:" + userId);
}

export async function saveDeviceWrap(userId, amk) {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const iv = randomBytes(IV_BYTES);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: deviceWrapAad(userId) }, key, amk);
  await writeRecord(WRAP_STORE, { userId, key, iv, ciphertext: new Uint8Array(ciphertext) });
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
  try {
    const params = { name: "AES-GCM", iv: record.iv, additionalData: deviceWrapAad(userId) };
    return new Uint8Array(await crypto.subtle.decrypt(params, record.key, record.ciphertext));
  } catch (error) {
    return null;
  }
}

export async function clearDeviceWrap(userId) {
  await deleteRecord(WRAP_STORE, userId);
}
