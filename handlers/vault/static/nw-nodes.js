// Nodes, access grants and delegation certificates (contract sections 4 to 6).

import {
  absentField, aead, aeadOpen, concatBytes, decodeBase64Url, encodeBase64Url, fieldBool, fieldString,
  fieldU32, fieldU64, hash, kdf, pad, randomBytes, seal, sign, tlv, unpad, unwrap, utf8, utf8Decode, wrap,
} from "./nw-primitives.js";

const FACET_CONTEXT = "nwfacet1";
export const ROOT_COLLECTIONS = ["calendar", "contacts", "photos", "files"];
export const ROOT_NAMES = { calendar: "Calendar", contacts: "Contacts", photos: "Photos", files: "Files" };

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

export function grantMessage({ nodeId, principalType, principalId, role, facets, epoch, wrappedKeys }) {
  return tlv("nw-access-v1", fieldString(nodeId), fieldString(principalType), fieldString(principalId),
    fieldString(role), fieldString(facetsCsv(facets)), fieldU32(epoch), hash(wrappedKeys));
}

// createGrant seals a node key to a principal's encryption key and signs the
// grant with the granter's signing key.
export function createGrant({ nodeId, nodeKey, epoch, role, principalType, principalId, principalEncPub, granter, certId }) {
  const wrappedKeys = seal(principalEncPub, nodeKey);
  const grant = {
    nodeId, principalType, principalId, role, facets: null, epoch,
    wrappedKeys: encodeBase64Url(wrappedKeys),
    grantedByType: "user", grantedById: granter.userId, certId: null,
  };
  if (certId) {
    grant.certId = certId;
  }
  const message = grantMessage({ ...grant, wrappedKeys });
  grant.signature = encodeBase64Url(sign(granter.signSec, message));
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
