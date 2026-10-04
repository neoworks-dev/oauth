// Encrypts a secret with a non-extractable AES-GCM key that stays in IndexedDB.
// Script in this origin can use the key but cannot read it out.

import { randomBytes, utf8 } from "./nw-primitives.js";

const IV_BYTES = 12;

export async function wrapWithBrowserKey(bytes, aadText) {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const iv = randomBytes(IV_BYTES);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: utf8(aadText) }, key, bytes);
  return { key, iv, ciphertext: new Uint8Array(ciphertext) };
}

// unwrapWithBrowserKey returns the secret, or null if it cannot be opened.
export async function unwrapWithBrowserKey(wrapped, aadText) {
  try {
    const params = { name: "AES-GCM", iv: wrapped.iv, additionalData: utf8(aadText) };
    return new Uint8Array(await crypto.subtle.decrypt(params, wrapped.key, wrapped.ciphertext));
  } catch (error) {
    return null;
  }
}
