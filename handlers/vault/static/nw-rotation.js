// Full key rotation: a new identity replaces the old one, and the old one stays
// in the key bundle (wrapped under the new AMK) until every key sealed to it has
// been sealed to the new identity. An interrupted rotation therefore never
// leaves anything unreadable.

import { unwrapIdentity, wrapIdentity } from "./nw-account.js";
import { createGrant, nextLogPosition } from "./nw-nodes.js";
import { decodeBase64Url, encodeBase64Url, hash, sealOpen } from "./nw-primitives.js";

// previousIdentityPayload wraps the identity being replaced under the new AMK.
export function previousIdentityPayload({ amk, previousIdentity, userId, version }) {
  return {
    identityPrivate: encodeBase64Url(wrapIdentity(amk, previousIdentity, userId, version)),
    encPub: encodeBase64Url(previousIdentity.encPub),
    signPub: encodeBase64Url(previousIdentity.signPub),
  };
}

// openPreviousIdentity returns the identity an unfinished rotation replaced, or
// null when the bundle has none.
export function openPreviousIdentity(amk, bundle) {
  if (!bundle.previous) {
    return null;
  }
  return unwrapIdentity(amk, {
    userId: bundle.userId, version: bundle.version, identityPrivate: bundle.previous.identityPrivate,
    encPub: bundle.previous.encPub, signPub: bundle.previous.signPub,
  });
}

// ownRootGrants are the user's grants on nodes they own that are still sealed
// to the identity being replaced. Grants other people made stay with them.
export function ownRootGrants(tree, userId) {
  const owned = new Set(tree.nodes.filter((node) => node.ownerId === userId).map((node) => node.id));
  return tree.grants.filter((grant) => owned.has(grant.nodeId));
}

// grantRequestBody is the body of POST /nodes/{id}/grants for a signed grant.
function grantRequestBody(grant, nodeId) {
  const wrappedKeysHash = encodeBase64Url(hash(decodeBase64Url(grant.wrappedKeys)));
  return {
    grant: {
      principalType: grant.principalType, principalId: grant.principalId, role: grant.role,
      facets: null, epoch: grant.epoch, wrappedKeys: grant.wrappedKeys,
    },
    entry: {
      nodeId, index: grant.logIndex, prevHash: grant.prevHash, action: "grant",
      principalType: grant.principalType, principalId: grant.principalId, role: grant.role,
      facets: null, epoch: grant.epoch, wrappedKeysHash, actorType: "user", actorId: grant.grantedById,
      certId: null, signature: grant.signature,
    },
  };
}

// resealOwnGrants opens each of the user's own root grants with the previous
// identity and seals the node key to the new one, as a new entry in the node's
// access log signed by the new identity.
export function resealOwnGrants({ tree, userId, previousIdentity, identity }) {
  return ownRootGrants(tree, userId).map((own) => {
    const nodeKey = sealOpen(previousIdentity.encPub, previousIdentity.encSec, decodeBase64Url(own.wrappedKeys));
    const grant = createGrant({
      nodeId: own.nodeId, nodeKey, epoch: own.epoch, role: own.role, principalType: "user", principalId: userId,
      principalEncPub: identity.encPub, granter: { userId, signSec: identity.signSec },
      position: nextLogPosition(tree.heads[own.nodeId]),
    });
    return { nodeId: own.nodeId, body: grantRequestBody(grant, own.nodeId) };
  });
}

