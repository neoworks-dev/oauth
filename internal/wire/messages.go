package wire

// IdentityMessage is what selfSig signs.
func IdentityMessage(userID string, encPub, signPub []byte) []byte {
	return TLV("nw-identity-pub-v1", String(userID), encPub, signPub)
}

// GenesisPrevHash is the prevHash of a chain's entry 0: 32 zero bytes.
var GenesisPrevHash = make([]byte, 32)

// AccessEntryMessage is one access log entry (contract amendment 1): its bytes
// are what the actor signs and what the entry hash covers.
type AccessEntryMessage struct {
	NodeID          string
	Index           uint64
	PrevHash        []byte
	Action          string
	PrincipalType   string
	PrincipalID     string
	Role            string
	Facets          []uint32
	Epoch           uint32
	WrappedKeysHash []byte
	ActorType       string
	ActorID         string
	CertID          string
}

func (entry AccessEntryMessage) Bytes() []byte {
	return TLV("nw-access-entry-v1",
		String(entry.NodeID),
		U64(entry.Index),
		entry.PrevHash,
		String(entry.Action),
		String(entry.PrincipalType),
		String(entry.PrincipalID),
		String(entry.Role),
		String(FacetsCSV(entry.Facets)),
		U32(entry.Epoch),
		entry.WrappedKeysHash,
		String(entry.ActorType),
		String(entry.ActorID),
		String(entry.CertID),
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
