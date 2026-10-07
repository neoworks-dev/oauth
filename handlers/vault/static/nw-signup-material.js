// Everything a new account's browser generates (contract sections 3 to 5).

import {
  buildBundle, createIdentity, deriveRecoveryKek, derivePasswordKeys, newPwhashParams,
} from "./nw-account.js";
import { bytesToWords } from "./nw-recovery.js";
import { decodeBase64Url, encodeBase64Url, randomBytes, seal, wipe } from "./nw-primitives.js";

// createSignupMaterial derives all keys for a new account. It returns the
// request body for POST /vault/signup, the unlocked secrets to keep in memory
// and the recovery words to show once. Collection roots are created by the
// first consent that asks for each collection.
export function createSignupMaterial({ email, firstName, lastName, password, deviceId, deviceName, escrowPublicKey }) {
  const userId = crypto.randomUUID();
  const amk = randomBytes(32);
  const pwhash = newPwhashParams();
  const passwordKeys = derivePasswordKeys(password, pwhash);
  const recoveryEntropy = randomBytes(32);
  const identity = createIdentity();
  const bundle = buildBundle({
    userId, version: 1, amk, identity,
    passwordKek: passwordKeys.passwordKEK, recoveryKek: deriveRecoveryKek(recoveryEntropy),
  });
  const request = {
    email, firstName, lastName, userId, authKey: encodeBase64Url(passwordKeys.authKey), pwhash, bundle,
    device: { id: deviceId, name: deviceName },
  };
  if (escrowPublicKey) {
    request.escrow = { sealedAmk: encodeBase64Url(seal(decodeBase64Url(escrowPublicKey), amk)) };
  }
  wipe(passwordKeys.authKey);
  wipe(passwordKeys.passwordKEK);
  const recoveryWords = bytesToWords(recoveryEntropy);
  wipe(recoveryEntropy);
  return { request, amk, userId, recoveryWords };
}
