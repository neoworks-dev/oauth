// Reads a node's @neoworks.title: the descriptor names the title field's
// ordinal and the facet holding it; the facet's plaintext is an OpenSchema wire
// message in which a string field is a LEN field. Pure functions.

import { decryptFacet, parseContent, readVarint } from "./nw-nodes.js";
import { decodeBase64Url, utf8Decode } from "./nw-primitives.js";

const WIRE_VARINT = 0;
const WIRE_I64 = 1;
const WIRE_LEN = 2;
const WIRE_I32 = 5;

function skipField(bytes, wireType, offset) {
  if (wireType === WIRE_VARINT) {
    return readVarint(bytes, offset).next;
  }
  if (wireType === WIRE_I64) {
    return offset + 8;
  }
  if (wireType === WIRE_I32) {
    return offset + 4;
  }
  if (wireType === WIRE_LEN) {
    const length = readVarint(bytes, offset);
    return length.next + length.value;
  }
  throw new Error("unknown wire type");
}

// readStringField returns the first LEN field with the ordinal as text, or null.
export function readStringField(message, ordinal) {
  let offset = 0;
  while (offset < message.length) {
    const key = readVarint(message, offset);
    const wireType = key.value % 8;
    if (Math.floor(key.value / 8) === ordinal && wireType === WIRE_LEN) {
      const length = readVarint(message, key.next);
      return utf8Decode(message.subarray(length.next, length.next + length.value));
    }
    offset = skipField(message, wireType, key.next);
  }
  return null;
}

function titledFacet(descriptor, kind) {
  const nodeSchema = descriptor.nodes.find((entry) => entry.kind === kind);
  if (!nodeSchema || nodeSchema.title === null) {
    return null;
  }
  const facet = nodeSchema.facets.find((entry) => entry.fields.includes(nodeSchema.title));
  if (!facet) {
    return null;
  }
  return { ordinal: nodeSchema.title, tag: facet.tag };
}

// readTitle returns the node's title, or null when the descriptor names none for
// its kind, the node lacks the field or its facet does not decrypt.
export function readTitle(node, nodeKey, descriptor) {
  const titled = titledFacet(descriptor, node.kind);
  if (titled === null || !node.content) {
    return null;
  }
  try {
    const facet = parseContent(decodeBase64Url(node.content)).find((entry) => entry.tag === titled.tag);
    if (!facet) {
      return null;
    }
    return readStringField(decryptFacet(nodeKey, node, titled.tag, facet.ciphertext), titled.ordinal);
  } catch (error) {
    return null;
  }
}
