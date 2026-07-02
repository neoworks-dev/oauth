/**
 * Unit tests for the Vault's envelope-encryption design (vault.html). The Vault
 * logic lives in an HTML <script>, so these tests re-implement the exact same
 * primitive calls against libsodium + WebCrypto to prove the scheme round-trips:
 *
 *   AMK --keyed BLAKE2b--> seed --X25519--> account keypair
 *   DEK (random)         --crypto_box_seal(pub)--> wrappedDEK
 *   data                 --AES-GCM(DEK)--> [iv||ct]
 *   share: wrappedDEK --open(owner)--> DEK --seal(recipientPub)--> wrappedDEK'
 *
 * Run: cd apps/oauth/tests && bun test vault_envelope.test.ts
 */

import { describe, test, expect, beforeAll } from 'bun:test'
import _sodium from 'libsodium-wrappers-sumo'

const KEYPAIR_CONTEXT = 'nw-account-keypair-v1'
let sodium: typeof _sodium

beforeAll(async () => {
  await _sodium.ready
  sodium = _sodium
})

function deriveKeypair(amk: Uint8Array) {
  const seed = sodium.crypto_generichash(32, sodium.from_string(KEYPAIR_CONTEXT), amk)
  return sodium.crypto_box_seed_keypair(seed)
}

function sealDek(dek: Uint8Array, pub: Uint8Array): Uint8Array {
  return sodium.crypto_box_seal(dek, pub)
}

function openDek(wrapped: Uint8Array, kp: { publicKey: Uint8Array; privateKey: Uint8Array }): Uint8Array | null {
  return sodium.crypto_box_seal_open(wrapped, kp.publicKey, kp.privateKey)
}

async function aesEncrypt(dek: Uint8Array, plain: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', dek, 'AES-GCM', false, ['encrypt', 'decrypt'])
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain))
  const out = new Uint8Array(12 + ct.length)
  out.set(iv, 0)
  out.set(ct, 12)
  return out
}

async function aesDecrypt(dek: Uint8Array, enc: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', dek, 'AES-GCM', false, ['encrypt', 'decrypt'])
  const iv = enc.slice(0, 12)
  const ct = enc.slice(12)
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct))
}

describe('vault envelope', () => {
  test('keypair derivation from AMK is deterministic', () => {
    const amk = new Uint8Array(32).fill(7)
    const a = deriveKeypair(amk)
    const b = deriveKeypair(amk)
    expect(sodium.to_base64(a.publicKey)).toBe(sodium.to_base64(b.publicKey))

    const other = deriveKeypair(new Uint8Array(32).fill(9))
    expect(sodium.to_base64(a.publicKey)).not.toBe(sodium.to_base64(other.publicKey))
  })

  test('self round-trip: seal DEK to own key, encrypt, decrypt', async () => {
    const owner = deriveKeypair(crypto.getRandomValues(new Uint8Array(32)))
    const dek = crypto.getRandomValues(new Uint8Array(32))
    const wrapped = sealDek(dek, owner.publicKey)

    const plain = new TextEncoder().encode('a secret note')
    const enc = await aesEncrypt(dek, plain)

    const recoveredDek = openDek(wrapped, owner)
    expect(recoveredDek).not.toBeNull()
    const dec = await aesDecrypt(recoveredDek as Uint8Array, enc)
    expect(new TextDecoder().decode(dec)).toBe('a secret note')
  })

  test('share: rewrap to recipient lets only the recipient open it', async () => {
    const owner = deriveKeypair(crypto.getRandomValues(new Uint8Array(32)))
    const recipient = deriveKeypair(crypto.getRandomValues(new Uint8Array(32)))
    const stranger = deriveKeypair(crypto.getRandomValues(new Uint8Array(32)))

    const dek = crypto.getRandomValues(new Uint8Array(32))
    const wrappedForOwner = sealDek(dek, owner.publicKey)

    // Owner unseals and re-seals to the recipient (vault rewrap).
    const dekAtOwner = openDek(wrappedForOwner, owner)
    expect(dekAtOwner).not.toBeNull()
    const wrappedForRecipient = sealDek(dekAtOwner as Uint8Array, recipient.publicKey)

    // Recipient can open their wrapper and gets the SAME dek.
    const dekAtRecipient = openDek(wrappedForRecipient, recipient)
    expect(dekAtRecipient).not.toBeNull()
    expect(sodium.to_base64(dekAtRecipient as Uint8Array)).toBe(sodium.to_base64(dek))

    // A stranger cannot open the recipient's wrapper (seal_open rejects a wrong
    // key — by null on some builds, by throwing on others; either is a failure).
    expect(() => {
      const d = openDek(wrappedForRecipient, stranger)
      if (d === null) throw new Error('null')
    }).toThrow()
    // The recipient cannot open the owner's own wrapper.
    expect(() => {
      const d = openDek(wrappedForOwner, recipient)
      if (d === null) throw new Error('null')
    }).toThrow()
  })

  test('multi-chunk: one DEK encrypts every chunk independently', async () => {
    const owner = deriveKeypair(crypto.getRandomValues(new Uint8Array(32)))
    const dek = crypto.getRandomValues(new Uint8Array(32))
    const wrapped = sealDek(dek, owner.publicKey)

    const chunks = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6, 7]), new Uint8Array([8])]
    const encrypted = await Promise.all(chunks.map((c) => aesEncrypt(dek, c)))

    const recoveredDek = openDek(wrapped, owner) as Uint8Array
    for (let i = 0; i < chunks.length; i++) {
      const dec = await aesDecrypt(recoveredDek, encrypted[i])
      expect(Array.from(dec)).toEqual(Array.from(chunks[i]))
    }
  })
})
