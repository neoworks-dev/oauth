// The escrow service's X25519 public key, pinned in the vault build. Signup seals
// the AMK to it when the user chooses recovery help. Replace it with the key
// printed by `escrow keygen` for a deployment. This default is the development key.
export const ESCROW_PUBLIC_KEY = null;
