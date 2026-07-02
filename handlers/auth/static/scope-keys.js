// Per-scope key derivation for the scope-bound E2E decryption pipeline.
//
// The key-holder (the Vault iframe on web, the authenticator on native) derives
// a distinct X25519 keypair per encryption scope from the AMK. An object in
// scope S has its DEK sealed to pub_S; only a caller whose OAuth token carries a
// read grant for S gets the key-holder to derive priv_S and unseal it. Because
// the binding IS the keypair choice, cross-scope decryption is cryptographically
// impossible — no AAD, no per-object grant table.
//
// Environment-agnostic, mirroring chat-ratchet.js: `createScopeKeys(sodium)`
// takes a ready libsodium instance. The Vault calls it with its global `sodium`;
// the test suite imports libsodium-wrappers-sumo and calls it identically, so the
// shipped code is the code under test. The literal AMK never leaves the caller —
// this module only reads it to derive, and never persists or zeroes it (the
// caller owns the AMK's lifetime).

// Legacy account-keypair context — kept so pre-migration objects (sealed to the
// single account key) stay readable. New objects use per-scope keys.
const ACCOUNT_CONTEXT = 'nw-account-keypair-v1';
// Resident scope-derivation secret: blake2b(AMK, this). Lets the key-holder zero
// the literal AMK after unlock yet still derive scope keys lazily. It is no more
// sensitive than the account private key the Vault already keeps resident.
const SCOPE_MASTER_CONTEXT = 'nw-scope-master-v1';
const SCOPE_KEYPAIR_PREFIX = 'nw-scope-keypair-v1:';

// Actions that imply the holder may read (and therefore decrypt) a scope's data.
const READ_ACTIONS = new Set(['read', 'write', 'admin', '*']);

/**
 * Parse an OAuth scope string of the form `[organization:]entity:action`.
 * The encryption `label` keys the per-scope keypair; org-scoped data lives in a
 * distinct keyspace (`org:entity`) so two orgs' same-named entities never share
 * a key. OIDC scopes (openid/profile/email) have no action and are not
 * encryption scopes — they yield a null action.
 */
export function parseScope(scope) {
	const parts = scope.split(':');
	if (parts.length === 3) {
		return { org: parts[0], entity: parts[1], action: parts[2], label: parts[0] + ':' + parts[1] };
	}
	if (parts.length === 2) {
		return { org: null, entity: parts[0], action: parts[1], label: parts[0] };
	}
	return { org: null, entity: scope, action: null, label: scope };
}

/**
 * Given the granted OAuth scopes from a verified access token, return the set of
 * encryption labels the caller may decrypt. A label is decryptable when any
 * granted scope for it carries a read-implying action.
 */
export function decryptableLabels(grantedScopes) {
	const labels = new Set();
	for (const scope of grantedScopes || []) {
		const parsed = parseScope(scope);
		if (parsed.action && READ_ACTIONS.has(parsed.action)) {
			labels.add(parsed.label);
		}
	}
	return labels;
}

export function createScopeKeys(sodium) {
	function keypairFromContext(secret, context) {
		const seed = sodium.crypto_generichash(32, sodium.from_string(context), secret);
		const keypair = sodium.crypto_box_seed_keypair(seed);
		sodium.memzero(seed);
		return keypair;
	}

	// Derive the resident scope-master secret from the AMK. Call once at unlock,
	// keep the result, then the AMK may be zeroed.
	function deriveScopeMaster(amkBytes) {
		return sodium.crypto_generichash(32, sodium.from_string(SCOPE_MASTER_CONTEXT), amkBytes);
	}

	// Per-scope X25519 keypair from the scope-master secret + encryption label.
	function scopeKeypair(scopeMaster, label) {
		return keypairFromContext(scopeMaster, SCOPE_KEYPAIR_PREFIX + label);
	}

	// Legacy single account keypair, derived straight from the AMK. Used only to
	// read pre-migration objects.
	function accountKeypair(amkBytes) {
		return keypairFromContext(amkBytes, ACCOUNT_CONTEXT);
	}

	return { deriveScopeMaster, scopeKeypair, accountKeypair };
}
