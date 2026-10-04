// Account-level operations that change key material: password change and
// rotation. Each one re-derives keys from the password the user just typed.

import {
  buildBundle, createIdentity, derivePasswordKeys, deriveRecoveryKek, newPwhashParams, unwrapAmk, wrapAmk,
} from "./nw-account.js";
import { ApiError, callApi, getJson, postJson } from "./nw-api.js";
import { previousIdentityPayload, resealOwnGrants } from "./nw-rotation.js";
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
  return prepareRotation(bundle, password, escrow, requireUnlocked().identity);
}

// prepareFullRotation is a light rotation with a new identity. The replaced
// identity travels in the bundle until finishRotation has resealed every key.
export function prepareFullRotation(bundle, password, escrow) {
  return prepareRotation(bundle, password, escrow, createIdentity());
}

function prepareRotation(bundle, password, escrow, identity) {
  const { userId, identity: currentIdentity, previousIdentity } = requireUnlocked();
  const currentAuthKey = proveCurrentPassword(bundle, userId, password);
  const amk = randomBytes(32);
  const pwhash = newPwhashParams();
  const passwordKeys = derivePasswordKeys(password, pwhash);
  const recoveryEntropy = randomBytes(32);
  const nextBundle = buildBundle({
    userId, version: bundle.version + 1, amk, identity,
    passwordKek: passwordKeys.passwordKEK, recoveryKek: deriveRecoveryKek(recoveryEntropy),
  });
  const replaced = replacedIdentity(identity, currentIdentity, previousIdentity);
  if (replaced !== null) {
    nextBundle.previous = previousIdentityPayload({ amk, previousIdentity: replaced, userId, version: nextBundle.version });
  }
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

// replacedIdentity is the identity the next bundle has to keep: the current one
// when the identity changes, otherwise the unfinished rotation's, if any.
function replacedIdentity(nextIdentity, currentIdentity, previousIdentity) {
  if (nextIdentity !== currentIdentity) {
    return currentIdentity;
  }
  return previousIdentity;
}

// commitRotation sends the prepared rotation and switches the keystore to the
// new AMK and bundle.
export async function commitRotation(prepared) {
  await postJson("/vault/rotate", prepared.request);
  const bundle = await getJson("/vault/bundle");
  unlock(prepared.amk, bundle);
  wipe(prepared.recoveryEntropy);
}

const RESEAL_ATTEMPTS = 3;

// finishRotation seals the user's own root keys to the new identity and then
// tells the server to drop the previous one. It can be run again after an
// interruption, because the previous identity is still in the bundle.
export async function finishRotation(apiUrl, password) {
  const { userId, identity, previousIdentity } = requireUnlocked();
  if (previousIdentity === null) {
    return;
  }
  const bundle = await getJson("/vault/bundle");
  const authKey = proveCurrentPassword(bundle, userId, password);
  await resealWithRetries(apiUrl, userId, previousIdentity, identity);
  await postJson("/vault/rotate/complete", { currentAuthKey: encodeBase64Url(authKey), version: bundle.version });
  wipe(authKey);
  unlock(requireUnlocked().amk, await getJson("/vault/bundle"));
}

async function resealWithRetries(apiUrl, userId, previousIdentity, identity) {
  for (let attempt = 1; ; attempt += 1) {
    const tree = await getJson("/vault/tree");
    try {
      await postResealed(apiUrl, resealOwnGrants({ tree, userId, previousIdentity, identity }));
      return;
    } catch (error) {
      if (!(error instanceof ApiError) || error.code !== "log_head_moved" || attempt >= RESEAL_ATTEMPTS) {
        throw error;
      }
    }
  }
}

async function postResealed(apiUrl, requests) {
  for (const request of requests) {
    await callApi(apiUrl, "POST", "/api/v1/nodes/" + request.nodeId + "/grants", request.body);
  }
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
