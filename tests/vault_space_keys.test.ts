/**
 * Unit tests for the space-key crypto module (space-keys.js) — imported
 * verbatim, so the shipped Vault code is the code under test.
 *
 *   AMK --keyed BLAKE2b--> Ed25519 signing keypair (account-level)
 *   space key (random 32B, per epoch) --crypto_box_seal(scope pub)--> wrapped_key
 *   row key = keyed BLAKE2b(space key, "nw-space-item:" + itemId)
 *   row     --AES-GCM(row key, AAD = envelope header)--> [iv||ct]
 *   sig     = Ed25519 over blake2b(AAD || blob)
 *
 * Run: cd apps/oauth/tests && bun test vault_space_keys.test.ts
 */

import { describe, test, expect, beforeAll } from 'bun:test'
import _sodium from 'libsodium-wrappers-sumo'
// @ts-ignore plain JS module shared with the Vault iframe
import { createSpaceKeys } from '../handlers/auth/static/space-keys.js'
// @ts-ignore plain JS module shared with the Vault iframe
import { createScopeKeys } from '../handlers/auth/static/scope-keys.js'

let sodium: typeof _sodium

function b64(bytes: Uint8Array): string {
  return sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL)
}
let spaceApi: ReturnType<typeof createSpaceKeys>
let scopeApi: ReturnType<typeof createScopeKeys>

beforeAll(async () => {
  await _sodium.ready
  sodium = _sodium
  spaceApi = createSpaceKeys(sodium)
  scopeApi = createScopeKeys(sodium)
})

function scopeKeypairFor(amk: Uint8Array, label: string) {
  const master = scopeApi.deriveScopeMaster(amk)
  return scopeApi.scopeKeypair(master, label)
}

async function aesGcm(rowKey: Uint8Array, aad: Uint8Array, plain: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', rowKey, 'AES-GCM', false, ['encrypt', 'decrypt'])
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, plain)
  )
  const out = new Uint8Array(12 + ct.length)
  out.set(iv, 0)
  out.set(ct, 12)
  return out
}

async function aesGcmOpen(rowKey: Uint8Array, aad: Uint8Array, blob: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', rowKey, 'AES-GCM', false, ['encrypt', 'decrypt'])
  const iv = blob.slice(0, 12)
  const ct = blob.slice(12)
  return new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, ct)
  )
}

const header = {
  itemId: 'item-1111',
  spaceId: 'space-aaaa',
  collection: 'contacts',
  keyEpoch: 1,
  schemaVer: 1,
  baseSeq: 0,
  deleted: false
}

describe('space keys', () => {
  test('signing keypair derivation from AMK is deterministic', () => {
    const amk = new Uint8Array(32).fill(3)
    const a = spaceApi.deriveSigningKeypair(amk)
    const b = spaceApi.deriveSigningKeypair(new Uint8Array(32).fill(3))
    expect(sodium.to_base64(a.publicKey)).toBe(sodium.to_base64(b.publicKey))
    const other = spaceApi.deriveSigningKeypair(new Uint8Array(32).fill(4))
    expect(sodium.to_base64(a.publicKey)).not.toBe(sodium.to_base64(other.publicKey))
  })

  test('wrap/unwrap round-trip; wrong scope key fails', () => {
    const memberAmk = crypto.getRandomValues(new Uint8Array(32))
    const memberKp = scopeKeypairFor(memberAmk, 'contacts')
    const strangerKp = scopeKeypairFor(crypto.getRandomValues(new Uint8Array(32)), 'contacts')
    const wrongLabelKp = scopeKeypairFor(memberAmk, 'photos')

    const spaceKey = spaceApi.mintSpaceKey()
    const wrapped = spaceApi.wrapSpaceKey(spaceKey, b64(memberKp.publicKey))

    const opened = spaceApi.unwrapSpaceKey(wrapped, memberKp)
    expect(sodium.to_base64(opened)).toBe(sodium.to_base64(spaceKey))

    expect(() => spaceApi.unwrapSpaceKey(wrapped, strangerKp)).toThrow()
    // Cross-label unseal must fail: capability gating is the keypair choice.
    expect(() => spaceApi.unwrapSpaceKey(wrapped, wrongLabelKp)).toThrow()
  })

  test('wrap signature binds space, member, epoch, and the key itself', () => {
    const signer = spaceApi.deriveSigningKeypair(crypto.getRandomValues(new Uint8Array(32)))
    const signerPub = b64(signer.publicKey)
    const spaceKey = spaceApi.mintSpaceKey()

    const sig = spaceApi.signWrap('space-a', 'user-b', 2, spaceKey, signer.privateKey)
    expect(spaceApi.verifyWrap('space-a', 'user-b', 2, spaceKey, sig, signerPub)).toBe(true)
    expect(spaceApi.verifyWrap('space-X', 'user-b', 2, spaceKey, sig, signerPub)).toBe(false)
    expect(spaceApi.verifyWrap('space-a', 'user-X', 2, spaceKey, sig, signerPub)).toBe(false)
    expect(spaceApi.verifyWrap('space-a', 'user-b', 3, spaceKey, sig, signerPub)).toBe(false)
    expect(spaceApi.verifyWrap('space-a', 'user-b', 2, spaceApi.mintSpaceKey(), sig, signerPub)).toBe(false)
  })

  test('row encrypt/decrypt round-trips; AAD tamper fails the open', async () => {
    const spaceKey = spaceApi.mintSpaceKey()
    const rowKey = spaceApi.deriveRowKey(spaceKey, header.itemId)
    const aad = spaceApi.buildRowAad(header)
    const plain = new TextEncoder().encode('{"formatted_name":"Ada"}')

    const blob = await aesGcm(rowKey, aad, plain)
    const opened = await aesGcmOpen(rowKey, aad, blob)
    expect(new TextDecoder().decode(opened)).toBe('{"formatted_name":"Ada"}')

    // Flipping any bound header field must fail the GCM open.
    for (const tampered of [
      { ...header, keyEpoch: 2 },
      { ...header, baseSeq: 1 },
      { ...header, deleted: true },
      { ...header, spaceId: 'space-bbbb' },
      { ...header, itemId: 'item-2222' },
      { ...header, schemaVer: 2 }
    ]) {
      const badAad = spaceApi.buildRowAad(tampered)
      await expect(aesGcmOpen(rowKey, badAad, blob)).rejects.toThrow()
    }
  })

  test('row keys are distinct per item and per epoch key', () => {
    const keyA = spaceApi.mintSpaceKey()
    const keyB = spaceApi.mintSpaceKey()
    const rowA1 = spaceApi.deriveRowKey(keyA, 'item-1')
    const rowA2 = spaceApi.deriveRowKey(keyA, 'item-2')
    const rowB1 = spaceApi.deriveRowKey(keyB, 'item-1')
    expect(sodium.to_base64(rowA1)).not.toBe(sodium.to_base64(rowA2))
    expect(sodium.to_base64(rowA1)).not.toBe(sodium.to_base64(rowB1))
  })

  test('rotation isolation: the new epoch key cannot open old rows', async () => {
    const epoch1Key = spaceApi.mintSpaceKey()
    const epoch2Key = spaceApi.mintSpaceKey()
    const aad = spaceApi.buildRowAad(header)
    const blob = await aesGcm(spaceApi.deriveRowKey(epoch1Key, header.itemId), aad, new Uint8Array([1, 2, 3]))
    await expect(
      aesGcmOpen(spaceApi.deriveRowKey(epoch2Key, header.itemId), aad, blob)
    ).rejects.toThrow()
  })

  test('envelope signature verifies and rejects tampered blobs; tombstones sign empty', async () => {
    const signer = spaceApi.deriveSigningKeypair(crypto.getRandomValues(new Uint8Array(32)))
    const signerPub = b64(signer.publicKey)
    const forger = spaceApi.deriveSigningKeypair(crypto.getRandomValues(new Uint8Array(32)))
    const aad = spaceApi.buildRowAad(header)
    const blob = crypto.getRandomValues(new Uint8Array(64))

    const sig = spaceApi.signEnvelope(aad, blob, signer.privateKey)
    expect(spaceApi.verifyEnvelope(aad, blob, sig, signerPub)).toBe(true)

    const tampered = blob.slice()
    tampered[0] ^= 1
    expect(spaceApi.verifyEnvelope(aad, tampered, sig, signerPub)).toBe(false)

    // A member cannot forge another member's rows.
    const forgedSig = spaceApi.signEnvelope(aad, blob, forger.privateKey)
    expect(spaceApi.verifyEnvelope(aad, blob, forgedSig, signerPub)).toBe(false)

    // Tombstone: signature over the AAD with an empty blob.
    const tombstoneAad = spaceApi.buildRowAad({ ...header, deleted: true })
    const tombstoneSig = spaceApi.signEnvelope(tombstoneAad, new Uint8Array(0), signer.privateKey)
    expect(spaceApi.verifyEnvelope(tombstoneAad, new Uint8Array(0), tombstoneSig, signerPub)).toBe(true)
    // The live row's AAD must not verify against the tombstone signature.
    expect(spaceApi.verifyEnvelope(aad, new Uint8Array(0), tombstoneSig, signerPub)).toBe(false)
  })

  test('full share flow: mint, wrap to partner scope key, partner decrypts a row', async () => {
    const ownerSigner = spaceApi.deriveSigningKeypair(crypto.getRandomValues(new Uint8Array(32)))
    const partnerAmk = crypto.getRandomValues(new Uint8Array(32))
    const partnerScopeKp = scopeKeypairFor(partnerAmk, 'contacts')

    // Owner: mint, encrypt a row, sign, and wrap the key for the partner.
    const spaceKey = spaceApi.mintSpaceKey()
    const aad = spaceApi.buildRowAad(header)
    const plain = new TextEncoder().encode('shared event contact')
    const blob = await aesGcm(spaceApi.deriveRowKey(spaceKey, header.itemId), aad, plain)
    const sig = spaceApi.signEnvelope(aad, blob, ownerSigner.privateKey)
    const wrapped = spaceApi.wrapSpaceKey(spaceKey, b64(partnerScopeKp.publicKey))
    const wrapSig = spaceApi.signWrap('space-aaaa', 'partner-id', 1, spaceKey, ownerSigner.privateKey)

    // Partner: unwrap, verify wrap + envelope signatures, decrypt.
    const partnerKey = spaceApi.unwrapSpaceKey(wrapped, partnerScopeKp)
    const ownerSignerPub = b64(ownerSigner.publicKey)
    expect(spaceApi.verifyWrap('space-aaaa', 'partner-id', 1, partnerKey, wrapSig, ownerSignerPub)).toBe(true)
    expect(spaceApi.verifyEnvelope(aad, blob, sig, ownerSignerPub)).toBe(true)
    const opened = await aesGcmOpen(spaceApi.deriveRowKey(partnerKey, header.itemId), aad, blob)
    expect(new TextDecoder().decode(opened)).toBe('shared event contact')
  })
})
