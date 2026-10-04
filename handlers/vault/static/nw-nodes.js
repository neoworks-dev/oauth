// Nodes, access grants and delegation certificates (contract sections 4 to 6).

import {
  absentField, aead, aeadOpen, concatBytes, decodeBase64Url, encodeBase64Url, fieldBool, fieldString,
  fieldU32, fieldU64, hash, kdf, pad, randomBytes, seal, sign, tlv, unpad, unwrap, utf8, utf8Decode, wrap,
} from "./nw-primitives.js";

const FACET_CONTEXT = "nwfacet1";
export const ROOT_COLLECTIONS = ["calendar", "contacts", "photos", "files", "google"];
export const ROOT_NAMES = {
  calendar: "Calendar", contacts: "Contacts", photos: "Photos", files: "Files", google: "Google account",
};

export function facetKey(nodeKey, facet) {
  return kdf(nodeKey, facet, FACET_CONTEXT);
}

export function contentAad({ id, collection, facet, epoch, baseSeq, deleted }) {
  return tlv("nw-node-content-v1", fieldString(id), fieldString(collection), fieldU32(facet),
    fieldU32(epoch), fieldU64(baseSeq), fieldBool(deleted));
}

export function encryptFacet(nodeKey, node, facet, value) {
  const aad = contentAad({ ...node, facet });
  const plaintext = pad(utf8(JSON.stringify(value)));
  return aead(facetKey(nodeKey, facet), plaintext, aad);
}

export function decryptFacet(nodeKey, node, facet, ciphertext) {
  const aad = contentAad({ ...node, facet });
  const padded = aeadOpen(facetKey(nodeKey, facet), ciphertext, aad);
  return JSON.parse(utf8Decode(unpad(padded)));
}

function optionalString(text) {
  if (text === null || text === undefined) {
    return absentField;
  }
  return fieldString(text);
}

export function nodeKeyAad({ id, parentId, epoch, parentEpoch }) {
  return tlv("nw-node-key-v1", fieldString(id), optionalString(parentId), fieldU32(epoch), fieldU32(parentEpoch));
}

export function wrapNodeKey(parentKey, nodeKey, aadInfo) {
  return wrap(parentKey, nodeKey, nodeKeyAad(aadInfo));
}

export function unwrapNodeKey(parentKey, wrappedKey, aadInfo) {
  return unwrap(parentKey, wrappedKey, nodeKeyAad(aadInfo));
}

function hashOfFacets(content) {
  const parts = [];
  for (const entry of content) {
    parts.push(fieldU32(entry.facet), decodeBase64Url(entry.ciphertext));
  }
  return hash(concatBytes(...parts));
}

function optionalDecoded(text) {
  if (text === null || text === undefined) {
    return new Uint8Array(0);
  }
  return decodeBase64Url(text);
}

// canonicalBlobBytes is the blob descriptor as compact JSON with a fixed key
// order, the form the write signature covers.
export function canonicalBlobBytes(blob) {
  if (blob === null || blob === undefined) {
    return new Uint8Array(0);
  }
  const variants = blob.variants.map((variant) => ({
    name: variant.name, objectId: variant.objectId, chunks: variant.chunks, size: variant.size,
  }));
  return utf8(JSON.stringify({ objectId: blob.objectId, chunks: blob.chunks, size: blob.size, variants }));
}

// nodeWriteMessage is what an author signs. An absent wrappedKey or blob hashes
// as the empty string.
export function nodeWriteMessage(node) {
  return tlv("nw-node-write-v1", fieldString(node.id), optionalString(node.parentId), fieldString(node.collection),
    fieldString(node.kind), fieldU32(node.epoch), fieldU64(node.baseSeq), fieldBool(node.deleted),
    hash(optionalDecoded(node.wrappedKey)), hashOfFacets(node.content), hash(canonicalBlobBytes(node.blob)));
}

export function newId() {
  return crypto.randomUUID();
}

// createRootNode makes a collection root with a fresh random key. Its display
// name is encrypted as facet 0. The returned nodeKey is the only copy.
export function createRootNode({ userId, collection, identity }) {
  const nodeKey = randomBytes(32);
  const node = {
    id: newId(), parentId: null, ownerId: userId, collection, kind: "root", epoch: 1, wrappedKey: null,
    blob: null, deleted: false, baseSeq: 0, authorType: "user", authorId: userId, certId: null,
  };
  const ciphertext = encryptFacet(nodeKey, node, 0, { name: ROOT_NAMES[collection] });
  node.content = [{ facet: 0, ciphertext: encodeBase64Url(ciphertext) }];
  node.signature = encodeBase64Url(sign(identity.signSec, nodeWriteMessage(node)));
  return { node, nodeKey };
}

export function facetsCsv(facets) {
  if (!facets) {
    return "";
  }
  return facets.join(",");
}

// GENESIS_PREV_HASH is the prevHash of a chain's entry 0.
export const GENESIS_PREV_HASH = new Uint8Array(32);

// accessEntryBytes is what an access log entry's actor signs and what its
// hash covers (contract amendment 1).
export function accessEntryBytes(entry) {
  let certId = "";
  if (entry.certId) {
    certId = entry.certId;
  }
  return tlv("nw-access-entry-v1", fieldString(entry.nodeId), fieldU64(entry.index), entry.prevHash,
    fieldString(entry.action), fieldString(entry.principalType), fieldString(entry.principalId),
    fieldString(entry.role), fieldString(facetsCsv(entry.facets)), fieldU32(entry.epoch), entry.wrappedKeysHash,
    fieldString(entry.actorType), fieldString(entry.actorId), fieldString(certId));
}

// nextLogPosition is where the next entry of a node's access log goes, given
// the head the server reported for it ({ index, entryHash }) or none.
export function nextLogPosition(head) {
  if (!head) {
    return { index: 0, prevHash: GENESIS_PREV_HASH };
  }
  return { index: head.index + 1, prevHash: decodeBase64Url(head.entryHash) };
}

// createGrant seals a node key to a principal's encryption key and signs the
// grant's access log entry at the given chain position with the granter's
// signing key. A grant to an install names the install's certificate.
export function createGrant({ nodeId, nodeKey, epoch, role, principalType, principalId, principalEncPub, granter, certId, position }) {
  const wrappedKeys = seal(principalEncPub, nodeKey);
  const grant = {
    nodeId, principalType, principalId, role, facets: null, epoch,
    wrappedKeys: encodeBase64Url(wrappedKeys),
    grantedByType: "user", grantedById: granter.userId, certId: null,
    logIndex: position.index, prevHash: encodeBase64Url(position.prevHash),
  };
  if (certId) {
    grant.certId = certId;
  }
  const entryBytes = accessEntryBytes({
    nodeId, index: position.index, prevHash: position.prevHash, action: "grant", principalType, principalId,
    role, facets: null, epoch, wrappedKeysHash: hash(wrappedKeys), actorType: "user", actorId: granter.userId,
    certId: grant.certId,
  });
  grant.signature = encodeBase64Url(sign(granter.signSec, entryBytes));
  return grant;
}

export function delegationMessage(certificateBytes) {
  return tlv("nw-delegation-v1", certificateBytes);
}

// buildCertificate creates the delegation certificate for an install. The
// signature covers the exact JSON bytes, which travel as opaque bytes.
export function buildCertificate({ userId, clientId, install, scopes, signSec, lifetimeMs }) {
  const issuedAt = new Date();
  const document = {
    v: 1, certId: newId(), userId, installId: install.id, clientId,
    installEncPub: install.encPub, installSignPub: install.signPub, scopes,
    issuedAt: toRfc3339(issuedAt), expiresAt: toRfc3339(new Date(issuedAt.getTime() + lifetimeMs)),
  };
  const certificateBytes = utf8(JSON.stringify(document));
  const signature = sign(signSec, delegationMessage(certificateBytes));
  return {
    certId: document.certId,
    certificate: encodeBase64Url(certificateBytes),
    certificateSignature: encodeBase64Url(signature),
  };
}

function toRfc3339(date) {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}
