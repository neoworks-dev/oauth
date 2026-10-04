// Account-level operations that change key material: password change and
// rotation. Each one re-derives keys from the password the user just typed.

import {
  buildBundle, derivePasswordKeys, deriveRecoveryKek, newPwhashParams, unwrapAmk, wrapAmk,
} from "./nw-account.js";
import { getJson, postJson } from "./nw-api.js";
import { requireUnlocked, unlock } from "./nw-keystore.js";
import { decodeBase64Url, encodeBase64Url, randomBytes, seal, wipe } from "./nw-primitives.js";

function paramsOf(bundle) {
  return { salt: bundle.pwhashSalt, ops: bundle.pwhashOps, mem: bundle.pwhashMem };
}

// proveCurrentPassword derives the current keys and checks that they open the
// stored AMK wrap, so a wrong password fails before anything is sent.
function proveCurrentPassword(bundle, userId, password) {
  const keys = derivePasswordKeys(password, paramsOf(bundle));
  unwrapAmk(keys.passwordKEK, decodeBase64Url(bundle.amkPassword), userId, "password");
  wipe(keys.passwordKEK);
  return keys.authKey;
}

export async function changePassword(currentPassword, newPassword) {
  const { userId, amk } = requireUnlocked();
  const bundle = await getJson("/vault/bundle");
  const currentAuthKey = proveCurrentPassword(bundle, userId, currentPassword);
  const pwhash = newPwhashParams();
  const newKeys = derivePasswordKeys(newPassword, pwhash);
  const amkPassword = encodeBase64Url(wrapAmk(newKeys.passwordKEK, amk, userId, "password"));
  await postJson("/vault/password", {
    currentAuthKey: encodeBase64Url(currentAuthKey), newAuthKey: encodeBase64Url(newKeys.authKey),
    pwhash, amkPassword, expectedVersion: bundle.version,
  });
  wipe(newKeys.authKey);
  wipe(newKeys.passwordKEK);
  wipe(currentAuthKey);
}

// escrowChange says what a rotation does with the escrow wrap: "replace" seals
// the new AMK to the service key, "disable" drops the wrap, "none" leaves an
// account without escrow alone.
function escrowChange(escrow, amk) {
  if (escrow.mode === "replace") {
    return { sealedAmk: encodeBase64Url(seal(decodeBase64Url(escrow.publicKey), amk)) };
  }
  if (escrow.mode === "disable") {
    return { disable: true };
  }
  return null;
}

// prepareLightRotation derives everything for the next bundle version: a new
// AMK under the same identity, new password and recovery wraps. Nothing is sent.
export function prepareLightRotation(bundle, password, escrow) {
  const { userId, identity } = requireUnlocked();
  const currentAuthKey = proveCurrentPassword(bundle, userId, password);
  const amk = randomBytes(32);
  const pwhash = newPwhashParams();
  const passwordKeys = derivePasswordKeys(password, pwhash);
  const recoveryEntropy = randomBytes(32);
  const nextBundle = buildBundle({
    userId, version: bundle.version + 1, amk, identity,
    passwordKek: passwordKeys.passwordKEK, recoveryKek: deriveRecoveryKek(recoveryEntropy),
  });
  const request = {
    currentAuthKey: encodeBase64Url(currentAuthKey), newAuthKey: encodeBase64Url(passwordKeys.authKey), pwhash,
    amkPassword: nextBundle.amkPassword, expectedVersion: bundle.version, bundle: nextBundle,
  };
  const escrowRequest = escrowChange(escrow, amk);
  if (escrowRequest !== null) {
    request.escrow = escrowRequest;
  }
  wipe(currentAuthKey);
  wipe(passwordKeys.authKey);
  wipe(passwordKeys.passwordKEK);
  return { request, amk, recoveryEntropy };
}

// commitRotation sends the prepared rotation and switches the keystore to the
// new AMK and bundle.
export async function commitRotation(prepared) {
  await postJson("/vault/rotate", prepared.request);
  const bundle = await getJson("/vault/bundle");
  unlock(prepared.amk, bundle);
  wipe(prepared.recoveryEntropy);
}

// enableEscrow adds the escrow wrap to an account that chose "only you".
export async function enableEscrow(password, escrowPublicKey) {
  const { userId, amk } = requireUnlocked();
  const bundle = await getJson("/vault/bundle");
  const currentAuthKey = proveCurrentPassword(bundle, userId, password);
  await postJson("/vault/escrow/enable", {
    currentAuthKey: encodeBase64Url(currentAuthKey),
    sealedAmk: encodeBase64Url(seal(decodeBase64Url(escrowPublicKey), amk)),
  });
  wipe(currentAuthKey);
}
