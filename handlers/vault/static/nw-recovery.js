// Recovery key words: the 32 byte recovery entropy as 24 BIP39 English words
// (256 bits of entropy plus an 8-bit SHA-256 checksum, 11 bits per word).

import { BIP39_WORDS } from "./nw-bip39-words.js";

const ENTROPY_BYTES = 32;
const WORD_COUNT = 24;
const BITS_PER_WORD = 11;

function checksumByte(entropy) {
  return globalThis.sodium.crypto_hash_sha256(entropy)[0];
}

// bytesToWords encodes 32 bytes of entropy as 24 words.
export function bytesToWords(entropy) {
  if (entropy.length !== ENTROPY_BYTES) {
    throw new Error("Recovery entropy must be 32 bytes");
  }
  const bits = new Uint8Array(ENTROPY_BYTES + 1);
  bits.set(entropy);
  bits[ENTROPY_BYTES] = checksumByte(entropy);
  const words = [];
  for (let position = 0; position < WORD_COUNT; position += 1) {
    words.push(BIP39_WORDS[readBits(bits, position * BITS_PER_WORD)]);
  }
  return words;
}

function readBits(bytes, start) {
  let value = 0;
  for (let offset = 0; offset < BITS_PER_WORD; offset += 1) {
    const bit = start + offset;
    value = (value << 1) | ((bytes[bit >> 3] >> (7 - (bit & 7))) & 1);
  }
  return value;
}

// wordsToBytes is the inverse of bytesToWords. It throws on a wrong word count,
// an unknown word or a failed checksum.
export function wordsToBytes(words) {
  if (words.length !== WORD_COUNT) {
    throw new Error("A recovery key has " + WORD_COUNT + " words");
  }
  const bits = new Uint8Array(ENTROPY_BYTES + 1);
  words.forEach((word, position) => writeBits(bits, position * BITS_PER_WORD, indexOfWord(word)));
  const entropy = bits.slice(0, ENTROPY_BYTES);
  if (bits[ENTROPY_BYTES] !== checksumByte(entropy)) {
    throw new Error("The recovery words do not match their checksum");
  }
  return entropy;
}

function indexOfWord(word) {
  const index = BIP39_WORDS.indexOf(word.trim().toLowerCase());
  if (index === -1) {
    throw new Error("Unknown recovery word: " + word);
  }
  return index;
}

function writeBits(bytes, start, value) {
  for (let offset = 0; offset < BITS_PER_WORD; offset += 1) {
    const bit = start + offset;
    const set = (value >> (BITS_PER_WORD - 1 - offset)) & 1;
    bytes[bit >> 3] |= set << (7 - (bit & 7));
  }
}

// parseRecoveryWords accepts the words separated by spaces, commas or lines.
export function parseRecoveryWords(text) {
  const words = text.split(/[\s,]+/).filter((word) => word.length > 0);
  return wordsToBytes(words);
}

export function downloadRecoveryKey(words) {
  const lines = words.map((word, position) => (position + 1) + ". " + word);
  const content = "Neoworks recovery key\n" +
    "Keep this safe. It is the only way to recover your account if you forget your password.\n\n" +
    lines.join("\n") + "\n";
  const url = URL.createObjectURL(new Blob([content], { type: "text/plain" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "neoworks-recovery-key.txt";
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
