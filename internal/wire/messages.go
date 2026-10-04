package wire

// IdentityMessage is what selfSig signs.
func IdentityMessage(userID string, encPub, signPub []byte) []byte {
	return TLV("nw-identity-pub-v1", String(userID), encPub, signPub)
}

// AccessGrantMessage is what an access grant signature covers.
type AccessGrantMessage struct {
	NodeID        string
	PrincipalType string
	PrincipalID   string
	Role          string
	Facets        []uint32
	Epoch         uint32
	WrappedKeys   []byte
}

func (grant AccessGrantMessage) Bytes() []byte {
	return TLV("nw-access-v1",
		String(grant.NodeID),
		String(grant.PrincipalType),
		String(grant.PrincipalID),
		String(grant.Role),
		String(FacetsCSV(grant.Facets)),
		U32(grant.Epoch),
		Hash(grant.WrappedKeys),
	)
}

// DelegationMessage is what a delegation certificate signature covers.
func DelegationMessage(certificateBytes []byte) []byte {
	return TLV("nw-delegation-v1", certificateBytes)
}

// IdentityPrivateAAD is the AAD of the AMK-wrapped identity private keys.
func IdentityPrivateAAD(userID string, bundleVersion uint32) []byte {
	return TLV("nw-identity-v1", String(userID), U32(bundleVersion))
}

// AMKWrapAAD is the AAD of an AMK wrap; purpose is "password" or "recovery".
func AMKWrapAAD(userID, purpose string) []byte {
	return TLV("nw-amk-v1", String(userID), String(purpose))
}
