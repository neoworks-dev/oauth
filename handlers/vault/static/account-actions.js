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

// prepareLightRotation derives everything for the next bundle version: a new
// AMK under the same identity, new password and recovery wraps. Nothing is sent.
export function prepareLightRotation(bundle, password, { escrowEnabled, escrowPublicKey }) {
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
  if (escrowEnabled) {
    request.escrow = { sealedAmk: encodeBase64Url(seal(decodeBase64Url(escrowPublicKey), amk)) };
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
