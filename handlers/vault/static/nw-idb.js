// Small IndexedDB layer shared by the keystore and the escrow attempt store.

const DATABASE_NAME = "nw-vault";
const DATABASE_VERSION = 2;

export const WRAP_STORE = "device-wraps";
export const META_STORE = "meta";
export const ATTEMPT_STORE = "escrow-attempts";

function awaitRequest(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function upgrade(database) {
  const existing = database.objectStoreNames;
  if (!existing.contains(WRAP_STORE)) {
    database.createObjectStore(WRAP_STORE, { keyPath: "userId" });
  }
  if (!existing.contains(META_STORE)) {
    database.createObjectStore(META_STORE);
  }
  if (!existing.contains(ATTEMPT_STORE)) {
    database.createObjectStore(ATTEMPT_STORE, { keyPath: "userId" });
  }
}

function openDatabase() {
  const opening = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
  opening.onupgradeneeded = () => upgrade(opening.result);
  return awaitRequest(opening);
}

export async function readRecord(storeName, key) {
  const database = await openDatabase();
  const record = await awaitRequest(database.transaction(storeName).objectStore(storeName).get(key));
  database.close();
  return record;
}

// writeRecord stores a record. Stores with a key path take the key from the
// record; the others need an explicit key.
export async function writeRecord(storeName, record, key) {
  const database = await openDatabase();
  const store = database.transaction(storeName, "readwrite").objectStore(storeName);
  if (key === undefined) {
    await awaitRequest(store.put(record));
  } else {
    await awaitRequest(store.put(record, key));
  }
  database.close();
}

export async function deleteRecord(storeName, key) {
  const database = await openDatabase();
  await awaitRequest(database.transaction(storeName, "readwrite").objectStore(storeName).delete(key));
  database.close();
}
