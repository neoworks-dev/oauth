// Byte-level building blocks of the Neoworks crypto contract: tlv framing and
// the libsodium primitives. All other modules build on these.

const NONCE_BYTES = 24;
const PAD_BLOCK = 256;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function lib() {
  return globalThis.sodium;
}

export async function ready() {
  await lib().ready;
}

export function randomBytes(size) {
  return lib().randombytes_buf(size);
}

export function wipe(bytes) {
  lib().memzero(bytes);
}

export function utf8(text) {
  return textEncoder.encode(text);
}

export function utf8Decode(bytes) {
  return textDecoder.decode(bytes);
}

export function encodeBase64Url(bytes) {
  return lib().to_base64(bytes, lib().base64_variants.URLSAFE_NO_PADDING);
}

export function decodeBase64Url(text) {
  return lib().from_base64(text, lib().base64_variants.URLSAFE_NO_PADDING);
}

export function concatBytes(...parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.length;
  }
  return joined;
}

export function bytesEqual(left, right) {
  return lib().memcmp(left, right);
}

// ── tlv ──────────────────────────────────────────────────────────────────────
// tlv(context, fields...) = utf8(context) 0x00, then every field as
// u32be(length) followed by its bytes. Fields are Uint8Arrays; build them with
// the field helpers below. An absent optional value is a zero-length field.

export function fieldString(text) {
  return utf8(text);
}

export function fieldU8(value) {
  return Uint8Array.of(value);
}

export function fieldU32(value) {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value);
  return bytes;
}

export function fieldU64(value) {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value));
  return bytes;
}

export function fieldBool(value) {
  if (value) {
    return fieldU8(1);
  }
  return fieldU8(0);
}

export const absentField = new Uint8Array(0);

function frameField(field) {
  return concatBytes(fieldU32(field.length), field);
}

export function tlv(context, ...fields) {
  return concatBytes(utf8(context), Uint8Array.of(0), ...fields.map(frameField));
}

// ── primitives ───────────────────────────────────────────────────────────────

export function aead(key, message, aad) {
  const nonce = randomBytes(NONCE_BYTES);
  const sealed = lib().crypto_aead_xchacha20poly1305_ietf_encrypt(message, aad, null, nonce, key);
  return concatBytes(nonce, sealed);
}

export function aeadOpen(key, boxed, aad) {
  const nonce = boxed.slice(0, NONCE_BYTES);
  const sealed = boxed.slice(NONCE_BYTES);
  return lib().crypto_aead_xchacha20poly1305_ietf_decrypt(null, sealed, aad, nonce, key);
}

export function wrap(kek, key, aad) {
  return aead(kek, key, aad);
}

export function unwrap(kek, wrapped, aad) {
  return aeadOpen(kek, wrapped, aad);
}

export function seal(publicKey, message) {
  return lib().crypto_box_seal(message, publicKey);
}

export function sealOpen(publicKey, secretKey, sealed) {
  return lib().crypto_box_seal_open(sealed, publicKey, secretKey);
}

export function kdf(key, id, context) {
  return lib().crypto_kdf_derive_from_key(32, id, context, key);
}

export function hash(data) {
  return lib().crypto_generichash(32, data);
}

export function sign(secretKey, message) {
  return lib().crypto_sign_detached(message, secretKey);
}

export function verify(publicKey, message, signature) {
  return lib().crypto_sign_verify_detached(signature, message, publicKey);
}

export function boxKeypair() {
  const pair = lib().crypto_box_keypair();
  return { publicKey: pair.publicKey, secretKey: pair.privateKey };
}

export function signKeypair() {
  const pair = lib().crypto_sign_keypair();
  return { publicKey: pair.publicKey, secretKey: pair.privateKey };
}

export function pwhash(password, salt, ops, mem) {
  return lib().crypto_pwhash(32, password, salt, ops, mem, lib().crypto_pwhash_ALG_ARGON2ID13);
}

export function pad(data) {
  return lib().pad(data, PAD_BLOCK);
}

export function unpad(data) {
  return lib().unpad(data, PAD_BLOCK);
}
