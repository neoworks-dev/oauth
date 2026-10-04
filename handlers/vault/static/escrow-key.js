// The escrow service's X25519 public key, pinned in the vault build. Signup seals
// the AMK to it when the user chooses recovery help. For a deployment, replace it
// with the key printed by `escrow pubkey`. This default is the development key
// that `ESCROW_DEV=true` selects.
export const ESCROW_PUBLIC_KEY = "6_KNXzAVLLaD5A4Jt8co9OWhFE9M4s4IHVMLMwFF4Uw";
