// Everything a new account's browser generates (contract sections 3 to 5).

import {
  buildBundle, createIdentity, deriveRecoveryKek, derivePasswordKeys, newPwhashParams,
} from "./nw-account.js";
import { ROOT_COLLECTIONS, createGrant, createRootNode } from "./nw-nodes.js";
import { bytesToWords } from "./nw-recovery.js";
import { decodeBase64Url, encodeBase64Url, randomBytes, seal, wipe } from "./nw-primitives.js";

function buildRoots(userId, identity) {
  const nodes = [];
  const grants = [];
  for (const collection of ROOT_COLLECTIONS) {
    const { node, nodeKey } = createRootNode({ userId, collection, identity });
    nodes.push(node);
    grants.push(createGrant({
      nodeId: node.id, nodeKey, epoch: node.epoch, role: "admin", principalType: "user", principalId: userId,
      principalEncPub: identity.encPub, granter: { userId, signSec: identity.signSec },
    }));
    wipe(nodeKey);
  }
  return { nodes, grants };
}

// createSignupMaterial derives all keys for a new account. It returns the
// request body for POST /vault/signup, the unlocked secrets to keep in memory
// and the recovery words to show once.
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
  const { nodes, grants } = buildRoots(userId, identity);
  const request = {
    email, firstName, lastName, userId, authKey: encodeBase64Url(passwordKeys.authKey), pwhash, bundle, nodes, grants,
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
