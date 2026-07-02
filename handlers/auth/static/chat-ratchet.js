// Double Ratchet + X3DH over libsodium, as a Signal-style session engine.
//
// This module is environment-agnostic: `createRatchet(sodium)` takes a ready
// libsodium instance and returns the session operations. The Vault iframe calls
// it with its global `sodium`; the test suite imports libsodium-wrappers-sumo and
// calls it the same way, so the exact code that ships is the code under test.
//
// Session state is plain JSON (base64 fields) so the Vault can seal it under an
// AMK-derived key and the app can persist the opaque blob — the server stores
// nothing. All key material is base64; raw bytes never escape this module.
//
// References: Signal "The Double Ratchet Algorithm" and "X3DH". Primitives:
//   DH      = X25519 (crypto_scalarmult)
//   KDF_RK  = HKDF-SHA256
//   KDF_CK  = HMAC-SHA256 (0x01 → message key, 0x02 → next chain key)
//   AEAD    = XChaCha20-Poly1305 (nonce derived from the message key, not sent)

export function createRatchet(sodium) {
	const MAX_SKIP = 1000;
	const B64 = sodium.base64_variants.ORIGINAL;

	const enc = (u8) => sodium.to_base64(u8, B64);
	const dec = (s) => sodium.from_base64(s, B64);
	const utf8 = (s) => sodium.from_string(s);

	function concat(...parts) {
		let len = 0;
		for (const p of parts) len += p.length;
		const out = new Uint8Array(len);
		let off = 0;
		for (const p of parts) {
			out.set(p, off);
			off += p.length;
		}
		return out;
	}

	// HMAC-SHA256 with key as the first argument (libsodium takes message first).
	function hmac(key, message) {
		return sodium.crypto_auth_hmacsha256(message, key);
	}

	function hkdf(salt, ikm, info, length) {
		const prk = hmac(salt, ikm); // extract
		const infoBytes = utf8(info);
		const out = new Uint8Array(length);
		let prev = new Uint8Array(0);
		let off = 0;
		for (let i = 1; off < length; i++) {
			prev = hmac(prk, concat(prev, infoBytes, new Uint8Array([i])));
			const take = Math.min(prev.length, length - off);
			out.set(prev.subarray(0, take), off);
			off += take;
		}
		return out;
	}

	function dh(privB64, pubB64) {
		return sodium.crypto_scalarmult(dec(privB64), dec(pubB64));
	}

	function generateDH() {
		const kp = sodium.crypto_box_keypair();
		return { pub: enc(kp.publicKey), priv: enc(kp.privateKey) };
	}

	// Root KDF: advance the root key with a DH output, yielding the next root key
	// and a fresh chain key.
	function kdfRK(rkB64, dhOut) {
		const okm = hkdf(dec(rkB64), dhOut, 'nw-chat-ratchet-v1', 64);
		return { rk: enc(okm.subarray(0, 32)), ck: enc(okm.subarray(32, 64)) };
	}

	// Chain KDF: advance a chain key, yielding the next chain key and a message key.
	function kdfCK(ckB64) {
		const ck = dec(ckB64);
		const mk = hmac(ck, new Uint8Array([0x01]));
		const nextCK = hmac(ck, new Uint8Array([0x02]));
		return { ck: enc(nextCK), mk };
	}

	// Derive the AEAD key+nonce from the message key. The nonce is deterministic,
	// so it is never transmitted.
	function messageKeyParts(mk) {
		const okm = hkdf(new Uint8Array(32), mk, 'nw-chat-msg-v1', 32 + sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
		return {
			key: okm.subarray(0, 32),
			nonce: okm.subarray(32, 32 + sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES),
		};
	}

	function aeadEncrypt(mk, plaintext, ad) {
		const { key, nonce } = messageKeyParts(mk);
		return sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad, null, nonce, key);
	}

	function aeadDecrypt(mk, ciphertext, ad) {
		const { key, nonce } = messageKeyParts(mk);
		return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, ad, nonce, key);
	}

	function headerAD(header) {
		return utf8(JSON.stringify(header));
	}

	// ── X3DH ─────────────────────────────────────────────────────────────────

	const X3DH_PREFIX = new Uint8Array(32).fill(0xff);

	function x3dhSecret(parts) {
		const okm = hkdf(new Uint8Array(32), concat(X3DH_PREFIX, ...parts), 'nw-chat-x3dh-v1', 32);
		return enc(okm);
	}

	// Initiator: verify the recipient's signed prekey, run the four DHs, and return
	// an established session plus the X3DH header the first message must carry.
	function x3dhInitiator({ identityPriv, identityPub, bundle }) {
		const spk = bundle.signed_prekey;
		const okSig = sodium.crypto_sign_verify_detached(dec(spk.signature), dec(spk.public_key), dec(bundle.signing_key));
		if (!okSig) throw new Error('signed prekey signature invalid');

		const ek = generateDH();
		const parts = [
			dh(identityPriv, spk.public_key), // DH(IK_a, SPK_b)
			dh(ek.priv, bundle.identity_key), // DH(EK_a, IK_b)
			dh(ek.priv, spk.public_key),      // DH(EK_a, SPK_b)
		];
		const otpk = bundle.one_time_prekey || null;
		if (otpk) parts.push(dh(ek.priv, otpk.public_key)); // DH(EK_a, OPK_b)

		const sk = x3dhSecret(parts);
		const state = initAlice(sk, spk.public_key);
		return {
			state,
			x3dh: {
				ik: identityPub,
				ek: ek.pub,
				spk_id: spk.key_id,
				otpk_id: otpk ? otpk.key_id : null,
			},
		};
	}

	// Responder: mirror the four DHs using the stored prekey privates referenced by
	// the prekey header, then return the established session.
	function x3dhResponder({ identityPriv, signedPrekeyPub, signedPrekeyPriv, oneTimePrekeyPriv, remote }) {
		const parts = [
			dh(signedPrekeyPriv, remote.ik), // DH(IK_a, SPK_b)
			dh(identityPriv, remote.ek),     // DH(EK_a, IK_b)
			dh(signedPrekeyPriv, remote.ek), // DH(EK_a, SPK_b)
		];
		if (oneTimePrekeyPriv) parts.push(dh(oneTimePrekeyPriv, remote.ek)); // DH(EK_a, OPK_b)

		const sk = x3dhSecret(parts);
		return initBob(sk, { pub: signedPrekeyPub, priv: signedPrekeyPriv });
	}

	function initAlice(skB64, bobSignedPrekeyPub) {
		const dhs = generateDH();
		const { rk, ck } = kdfRK(skB64, dh(dhs.priv, bobSignedPrekeyPub));
		return {
			DHs: dhs,
			DHr: bobSignedPrekeyPub,
			RK: rk,
			CKs: ck,
			CKr: null,
			Ns: 0,
			Nr: 0,
			PN: 0,
			MKSKIPPED: {},
		};
	}

	function initBob(skB64, signedPrekeyKeypair) {
		return {
			DHs: signedPrekeyKeypair,
			DHr: null,
			RK: skB64,
			CKs: null,
			CKr: null,
			Ns: 0,
			Nr: 0,
			PN: 0,
			MKSKIPPED: {},
		};
	}

	// ── Ratchet ──────────────────────────────────────────────────────────────

	// Encrypt one message, advancing the sending chain. Returns the mutated state
	// and the wire message {header, ciphertext}. `extra` carries the X3DH header on
	// a prekey (first) message.
	function ratchetEncrypt(state, plaintext, extra) {
		const { ck, mk } = kdfCK(state.CKs);
		state.CKs = ck;
		const header = { dh: state.DHs.pub, pn: state.PN, n: state.Ns };
		if (extra) header.x3dh = extra;
		state.Ns += 1;
		const ciphertext = aeadEncrypt(mk, plaintext, headerAD(header));
		return { state, message: { header, ciphertext: enc(ciphertext) } };
	}

	// Decrypt one message, performing a DH ratchet step and/or skipping keys as the
	// header dictates. Out-of-order and missed messages resolve via MKSKIPPED.
	function ratchetDecrypt(state, message) {
		const header = message.header;

		const skipped = trySkipped(state, message);
		if (skipped) return { state, plaintext: skipped };

		if (header.dh !== state.DHr) {
			skipMessageKeys(state, header.pn);
			dhRatchet(state, header);
		}
		skipMessageKeys(state, header.n);

		const { ck, mk } = kdfCK(state.CKr);
		state.CKr = ck;
		state.Nr += 1;
		const plaintext = aeadDecrypt(mk, dec(message.ciphertext), headerAD(header));
		return { state, plaintext };
	}

	function trySkipped(state, message) {
		const key = message.header.dh + ':' + message.header.n;
		const mkB64 = state.MKSKIPPED[key];
		if (!mkB64) return null;
		delete state.MKSKIPPED[key];
		return aeadDecrypt(dec(mkB64), dec(message.ciphertext), headerAD(message.header));
	}

	function skipMessageKeys(state, until) {
		if (state.Nr + MAX_SKIP < until) throw new Error('too many skipped messages');
		if (!state.CKr) return;
		while (state.Nr < until) {
			const { ck, mk } = kdfCK(state.CKr);
			state.CKr = ck;
			state.MKSKIPPED[state.DHr + ':' + state.Nr] = enc(mk);
			state.Nr += 1;
		}
	}

	function dhRatchet(state, header) {
		state.PN = state.Ns;
		state.Ns = 0;
		state.Nr = 0;
		state.DHr = header.dh;
		let step = kdfRK(state.RK, dh(state.DHs.priv, state.DHr));
		state.RK = step.rk;
		state.CKr = step.ck;
		state.DHs = generateDH();
		step = kdfRK(state.RK, dh(state.DHs.priv, state.DHr));
		state.RK = step.rk;
		state.CKs = step.ck;
	}

	// ── Sender Keys (groups) ───────────────────────────────────────────────────
	//
	// Each member holds one symmetric sender chain per group plus an Ed25519 signing
	// key. A message is encrypted once with the sender's current message key and
	// broadcast to all members (fanned out by the relay). The sender key is shared
	// with each member device over the pairwise Double Ratchet as a "distribution"
	// blob. On membership change the sender rotates its key and redistributes.

	// Create this device's sender key for a group.
	function groupSenderCreate() {
		const signing = sodium.crypto_sign_keypair();
		return {
			chainKey: enc(sodium.randombytes_buf(32)),
			iteration: 0,
			signPub: enc(signing.publicKey),
			signPriv: enc(signing.privateKey),
		};
	}

	// The public half to hand to members (over pairwise sessions). Never includes
	// the signing private key.
	function groupSenderDistribution(senderState) {
		return {
			chainKey: senderState.chainKey,
			iteration: senderState.iteration,
			signPub: senderState.signPub,
		};
	}

	// Build a receiver-side view of another member's sender key from its distribution.
	function groupReceiverFromDistribution(distribution) {
		return {
			chainKey: distribution.chainKey,
			iteration: distribution.iteration,
			signPub: distribution.signPub,
			skipped: {},
		};
	}

	// Encrypt + sign one group message, advancing the sender chain.
	function groupEncrypt(senderState, plaintext) {
		const { ck, mk } = kdfCK(senderState.chainKey);
		const header = { iteration: senderState.iteration };
		senderState.chainKey = ck;
		senderState.iteration += 1;
		const ciphertext = aeadEncrypt(mk, plaintext, headerAD(header));
		const signature = sodium.crypto_sign_detached(ciphertext, dec(senderState.signPriv));
		return {
			state: senderState,
			message: { header, ciphertext: enc(ciphertext), signature: enc(signature) },
		};
	}

	// Verify + decrypt one group message, advancing/skipping the receiver chain.
	function groupDecrypt(receiverState, message) {
		const ciphertext = dec(message.ciphertext);
		const okSig = sodium.crypto_sign_verify_detached(dec(message.signature), ciphertext, dec(receiverState.signPub));
		if (!okSig) throw new Error('group message signature invalid');

		const target = message.header.iteration;
		let mk;
		if (target < receiverState.iteration) {
			const stored = receiverState.skipped[target];
			if (!stored) throw new Error('group message key unavailable');
			delete receiverState.skipped[target];
			mk = dec(stored);
		} else {
			if (receiverState.iteration + MAX_SKIP < target) throw new Error('too many skipped group messages');
			while (receiverState.iteration < target) {
				const step = kdfCK(receiverState.chainKey);
				receiverState.skipped[receiverState.iteration] = enc(step.mk);
				receiverState.chainKey = step.ck;
				receiverState.iteration += 1;
			}
			const step = kdfCK(receiverState.chainKey);
			receiverState.chainKey = step.ck;
			receiverState.iteration += 1;
			mk = step.mk;
		}

		const plaintext = aeadDecrypt(mk, ciphertext, headerAD(message.header));
		return { state: receiverState, plaintext };
	}

	return {
		x3dhInitiator,
		x3dhResponder,
		ratchetEncrypt,
		ratchetDecrypt,
		groupSenderCreate,
		groupSenderDistribution,
		groupReceiverFromDistribution,
		groupEncrypt,
		groupDecrypt,
	};
}
