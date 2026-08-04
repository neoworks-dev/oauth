// Space-key crypto for E2EE shared spaces (contacts first).
//
// A space is the unit of sharing: a 32-byte symmetric space key, epoch-versioned,
// sealed per member to their per-collection scope public key (crypto_box_seal).
// Row payloads are AES-256-GCM under a per-row key derived from the space key;
// the AAD binds the envelope header so ciphertext cannot be spliced across rows,
// spaces, or epochs. Authorship is provable: every envelope and every wrapped
// key carries an Ed25519 signature from the author's account-level signing
// keypair (derived from the AMK, so identical on all of a user's devices).
//
// Environment-agnostic, mirroring scope-keys.js: `createSpaceKeys(sodium)` takes
// a ready libsodium instance. The Vault calls it with its global `sodium`; the
// test suite imports libsodium-wrappers-sumo and calls it identically, so the
// shipped code is the code under test. AES-GCM itself runs in the caller via
// WebCrypto — this module only derives keys and builds AAD/signatures.

// Account-level Ed25519 signing identity: blake2b(AMK, this) → sign seed.
const SIGNING_CONTEXT = 'nw-space-signing-v1';
// Per-row key derivation: keyed BLAKE2b(space_key, this + item id). Keyed
// BLAKE2b is the codebase-standard KDF (see scope-keys.js); equivalent in role
// to HKDF here.
const ROW_KEY_PREFIX = 'nw-space-item:';
// Domain separators for the two signature contexts and the row AAD.
const WRAP_CONTEXT = 'nw-space-key-v1';
const AAD_CONTEXT = 'nw-space-item-v1';

export function createSpaceKeys(sodium) {
	const b64 = sodium.base64_variants.ORIGINAL;

	// Account-level Ed25519 signing keypair from the AMK. Same identity on every
	// device, so peers pin one signer key per user.
	function deriveSigningKeypair(amkBytes) {
		const seed = sodium.crypto_generichash(32, sodium.from_string(SIGNING_CONTEXT), amkBytes);
		const keypair = sodium.crypto_sign_seed_keypair(seed);
		sodium.memzero(seed);
		return keypair;
	}

	function mintSpaceKey() {
		return sodium.randombytes_buf(32);
	}

	// Seal the space key to a member's scope public key. Only that member's
	// Vault (holding the derived scope private key) can open it.
	function wrapSpaceKey(spaceKeyBytes, recipientPubKeyB64) {
		const recipientPub = sodium.from_base64(recipientPubKeyB64, b64);
		return sodium.to_base64(sodium.crypto_box_seal(spaceKeyBytes, recipientPub), b64);
	}

	function unwrapSpaceKey(wrappedB64, scopeKeypair) {
		const opened = sodium.crypto_box_seal_open(
			sodium.from_base64(wrappedB64, b64),
			scopeKeypair.publicKey,
			scopeKeypair.privateKey
		);
		if (!opened) throw new Error('cannot unseal space key');
		return opened;
	}

	// The signed wrap context. Signing includes the space key itself (via its
	// fingerprint), so a valid signature proves the signer knew the key — the
	// server cannot substitute key material and re-sign.
	function wrapContext(spaceId, memberUserId, epoch, spaceKeyBytes) {
		const fingerprint = sodium.to_base64(sodium.crypto_generichash(32, spaceKeyBytes), b64);
		return sodium.from_string(
			WRAP_CONTEXT + '|' + spaceId + '|' + memberUserId + '|' + epoch + '|' + fingerprint
		);
	}

	function signWrap(spaceId, memberUserId, epoch, spaceKeyBytes, signPrivateKey) {
		const context = wrapContext(spaceId, memberUserId, epoch, spaceKeyBytes);
		return sodium.to_base64(sodium.crypto_sign_detached(context, signPrivateKey), b64);
	}

	function verifyWrap(spaceId, memberUserId, epoch, spaceKeyBytes, signatureB64, signerPubB64) {
		const context = wrapContext(spaceId, memberUserId, epoch, spaceKeyBytes);
		return sodium.crypto_sign_verify_detached(
			sodium.from_base64(signatureB64, b64),
			context,
			sodium.from_base64(signerPubB64, b64)
		);
	}

	// Canonical row AAD. base_seq (not the server-assigned seq) — the client
	// encrypts before the server assigns. `deleted` is bound so a tombstone can
	// never be resurrected by replaying an old blob under a flipped flag.
	function buildRowAad(header) {
		return sodium.from_string(
			AAD_CONTEXT +
				'|' + header.itemId +
				'|' + header.spaceId +
				'|' + header.collection +
				'|' + header.keyEpoch +
				'|' + header.schemaVer +
				'|' + header.baseSeq +
				'|' + (header.deleted ? '1' : '0')
		);
	}

	// Per-row AES key from the space key — one derivation per row, no stored
	// per-row DEKs, rotation handled by epochs.
	function deriveRowKey(spaceKeyBytes, itemId) {
		return sodium.crypto_generichash(32, sodium.from_string(ROW_KEY_PREFIX + itemId), spaceKeyBytes);
	}

	// Envelope signature: Ed25519 over blake2b(AAD ‖ blob). Tombstones sign the
	// AAD with an empty blob.
	function envelopeDigest(aadBytes, blobBytes) {
		const joined = new Uint8Array(aadBytes.length + blobBytes.length);
		joined.set(aadBytes, 0);
		joined.set(blobBytes, aadBytes.length);
		return sodium.crypto_generichash(32, joined);
	}

	function signEnvelope(aadBytes, blobBytes, signPrivateKey) {
		return sodium.to_base64(
			sodium.crypto_sign_detached(envelopeDigest(aadBytes, blobBytes), signPrivateKey),
			b64
		);
	}

	function verifyEnvelope(aadBytes, blobBytes, signatureB64, signerPubB64) {
		return sodium.crypto_sign_verify_detached(
			sodium.from_base64(signatureB64, b64),
			envelopeDigest(aadBytes, blobBytes),
			sodium.from_base64(signerPubB64, b64)
		);
	}

	function keyFingerprint(keyBytes) {
		return sodium.to_base64(sodium.crypto_generichash(32, keyBytes), b64);
	}

	return {
		deriveSigningKeypair,
		mintSpaceKey,
		wrapSpaceKey,
		unwrapSpaceKey,
		signWrap,
		verifyWrap,
		buildRowAad,
		deriveRowKey,
		signEnvelope,
		verifyEnvelope,
		keyFingerprint
	};
}
