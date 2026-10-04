// Keeps an in-progress escrow recovery on this browser. The wait is days long,
// so the temporary secret that will open the released AMK is stored under a
// non-extractable browser key.

import { unwrapWithBrowserKey, wrapWithBrowserKey } from "./nw-browser-wrap.js";
import { ATTEMPT_STORE, deleteRecord, readRecord, writeRecord } from "./nw-idb.js";

function attemptAad(userId) {
  return "nw-escrow-attempt-v1:" + userId;
}

export async function saveAttempt(userId, { attemptId, claimSecret, readyAt, tempPub, tempSecret }) {
  const wrapped = await wrapWithBrowserKey(tempSecret, attemptAad(userId));
  await writeRecord(ATTEMPT_STORE, { userId, attemptId, claimSecret, readyAt, tempPub, ...wrapped });
}

// loadAttempt returns the stored attempt with its temporary secret opened, or
// null when there is none.
export async function loadAttempt(userId) {
  const record = await readRecord(ATTEMPT_STORE, userId);
  if (!record) {
    return null;
  }
  const tempSecret = await unwrapWithBrowserKey(record, attemptAad(userId));
  if (tempSecret === null) {
    return null;
  }
  return { attemptId: record.attemptId, claimSecret: record.claimSecret, readyAt: record.readyAt, tempPub: record.tempPub, tempSecret };
}

export async function clearAttempt(userId) {
  await deleteRecord(ATTEMPT_STORE, userId);
}
