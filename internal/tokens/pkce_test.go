package tokens

import "testing"

func TestVerifyPKCE(t *testing.T) {
	// RFC 7636 appendix B.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	if err := VerifyPKCE(verifier, challenge, "S256"); err != nil {
		t.Fatalf("the RFC vector must verify: %v", err)
	}
	if err := VerifyPKCE(verifier+"x", challenge, "S256"); err != ErrInvalidVerifier {
		t.Fatalf("a tampered verifier must fail, got %v", err)
	}
	if err := VerifyPKCE("", challenge, "S256"); err != ErrInvalidVerifier {
		t.Fatalf("an empty verifier must fail, got %v", err)
	}
	for _, method := range []string{"plain", "", "S512"} {
		if err := VerifyPKCE(verifier, verifier, method); err != ErrUnsupportedMethod {
			t.Fatalf("method %q must be refused, got %v", method, err)
		}
	}
}

func TestIssuerRoundTripAndRejection(t *testing.T) {
	issuer := newTestIssuer(t)
	signed, claims, err := issuer.IssueAccessToken(AccessTokenParams{UserID: "user-1", ClientID: "app", Scopes: []string{"openid"}, InstallID: "install-1"})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := issuer.VerifyAccessToken(signed)
	if err != nil || verified.Subject != "user-1" || verified.InstallID != "install-1" || verified.ID != claims.ID {
		t.Fatalf("unexpected claims %+v err %v", verified, err)
	}
	other := newTestIssuer(t)
	if _, err := other.VerifyAccessToken(signed); err != ErrTokenInvalid {
		t.Fatalf("a token from another key must be invalid, got %v", err)
	}
	if _, err := issuer.VerifyAccessToken(signed + "x"); err != ErrTokenInvalid {
		t.Fatalf("a tampered token must be invalid, got %v", err)
	}
}
