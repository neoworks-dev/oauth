// Account key construction (contract section 3): password split, AMK wraps and
// identity keypairs.

import {
  aeadOpen, boxKeypair, concatBytes, decodeBase64Url, encodeBase64Url, fieldString, fieldU32,
  kdf, pwhash, randomBytes, sign, signKeypair, tlv, unwrap, wrap, wipe,
} from "./nw-primitives.js";

export const PWHASH_OPS = 3;
export const PWHASH_MEM = 67108864;
export const PWHASH_SALT_BYTES = 16;
const AUTH_CONTEXT = "nwauth01";
const RECOVERY_CONTEXT = "nwrecov1";
const ENC_SECRET_BYTES = 32;

export function newPwhashParams() {
  return { salt: encodeBase64Url(randomBytes(PWHASH_SALT_BYTES)), ops: PWHASH_OPS, mem: PWHASH_MEM };
}

// derivePasswordKeys splits the Argon2id output into the key that proves the
// password to the server and the key that wraps the AMK. Only authKey leaves
// the device.
export function derivePasswordKeys(password, params) {
  const root = pwhash(password, decodeBase64Url(params.salt), params.ops, params.mem);
  const keys = { authKey: kdf(root, 1, AUTH_CONTEXT), passwordKEK: kdf(root, 2, AUTH_CONTEXT) };
  wipe(root);
  return keys;
}

export function deriveRecoveryKek(recoveryEntropy) {
  return kdf(recoveryEntropy, 1, RECOVERY_CONTEXT);
}

export function amkAad(userId, purpose) {
  return tlv("nw-amk-v1", fieldString(userId), fieldString(purpose));
}

export function wrapAmk(kek, amk, userId, purpose) {
  return wrap(kek, amk, amkAad(userId, purpose));
}

export function unwrapAmk(kek, wrappedAmk, userId, purpose) {
  return unwrap(kek, wrappedAmk, amkAad(userId, purpose));
}

export function identityAad(userId, bundleVersion) {
  return tlv("nw-identity-v1", fieldString(userId), fieldU32(bundleVersion));
}

export function createIdentity() {
  const encryption = boxKeypair();
  const signing = signKeypair();
  return {
    encPub: encryption.publicKey, encSec: encryption.secretKey,
    signPub: signing.publicKey, signSec: signing.secretKey,
  };
}

export function wrapIdentity(amk, identity, userId, bundleVersion) {
  const secrets = concatBytes(identity.encSec, identity.signSec);
  return wrap(amk, secrets, identityAad(userId, bundleVersion));
}

// unwrapIdentity needs the public keys to rebuild the keypairs, so it takes the
// bundle as the server returned it.
export function unwrapIdentity(amk, bundle) {
  const secrets = unwrap(amk, decodeBase64Url(bundle.identityPrivate), identityAad(bundle.userId, bundle.version));
  return {
    encPub: decodeBase64Url(bundle.encPub), encSec: secrets.slice(0, ENC_SECRET_BYTES),
    signPub: decodeBase64Url(bundle.signPub), signSec: secrets.slice(ENC_SECRET_BYTES),
  };
}

export function identityMessage(userId, encPub, signPub) {
  return tlv("nw-identity-pub-v1", fieldString(userId), encPub, signPub);
}

export function signIdentity(identity, userId) {
  return sign(identity.signSec, identityMessage(userId, identity.encPub, identity.signPub));
}

// signRotation links an identity to the one it replaces: the previous identity
// endorses the new keys as the given history version.
export function signRotation({ previousIdentity, identity, userId, identityVersion }) {
  const message = tlv("nw-identity-rotation-v1", fieldString(userId), fieldU32(identityVersion), identity.signPub, identity.encPub);
  return sign(previousIdentity.signSec, message);
}

// buildBundle assembles the key bundle payload a client sends to the server.
export function buildBundle({ userId, version, amk, identity, passwordKek, recoveryKek }) {
  return {
    version,
    amkPassword: encodeBase64Url(wrapAmk(passwordKek, amk, userId, "password")),
    amkRecovery: encodeBase64Url(wrapAmk(recoveryKek, amk, userId, "recovery")),
    identityPrivate: encodeBase64Url(wrapIdentity(amk, identity, userId, version)),
    encPub: encodeBase64Url(identity.encPub),
    signPub: encodeBase64Url(identity.signPub),
    selfSig: encodeBase64Url(signIdentity(identity, userId)),
  };
}

export function tryOpen(key, boxed, aad) {
  try {
    return aeadOpen(key, boxed, aad);
  } catch (error) {
    return null;
  }
}
