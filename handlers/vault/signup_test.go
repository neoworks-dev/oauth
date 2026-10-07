package vault

import (
	"strings"
	"testing"

	"github.com/neoworks/oauth/internal/testsupport"
	"github.com/neoworks/oauth/internal/wire"
)

func TestSignupWritesAccountAndSignsIn(t *testing.T) {
	vault := newTestVault(t)
	account := testsupport.NewAccount(uniqueEmail("signup"))
	vault.signUp(t, account)

	session := vault.browser.Do("GET", "/vault/session", nil, nil)
	if session.Body["authenticated"] != true || session.Body["userId"] != account.UserID {
		t.Fatalf("session: %s", session.Raw)
	}
	bundle := vault.browser.Do("GET", "/vault/bundle", nil, nil)
	if bundle.Status != 200 || bundle.Body["version"] != float64(1) || bundle.Body["encPub"] == nil {
		t.Fatalf("bundle: %d %s", bundle.Status, bundle.Raw)
	}
	tree := vault.browser.Do("GET", "/vault/tree", nil, nil)
	if tree.Status != 200 || len(tree.Body["nodes"].([]any)) != 0 || len(tree.Body["grants"].([]any)) != 0 {
		t.Fatalf("a new account has no roots until a consent asks for a collection: %d %s", tree.Status, tree.Raw)
	}
}

func TestSignupRequiresAVerifiedEmail(t *testing.T) {
	vault := newTestVault(t)
	account := testsupport.NewAccount(uniqueEmail("unverified"))
	response := vault.browser.Do("POST", "/vault/signup", account.SignupRequest(), nil)
	if response.Status != 403 {
		t.Fatalf("status %d, want 403", response.Status)
	}
}

func TestSignupRejectsTamperedKeyMaterial(t *testing.T) {
	cases := map[string]func(request map[string]any, account *testsupport.Account){
		"bad self signature": func(request map[string]any, account *testsupport.Account) {
			request["bundle"].(map[string]any)["selfSig"] = wire.EncodeBase64URL(make([]byte, 64))
		},
		"swapped enc key": func(request map[string]any, account *testsupport.Account) {
			request["bundle"].(map[string]any)["encPub"] = wire.EncodeBase64URL(testsupport.NewAccount("z@example.com").EncPub[:])
		},
		"weak argon params": func(request map[string]any, account *testsupport.Account) {
			request["pwhash"].(map[string]any)["ops"] = 1
		},
		"non uuid user id": func(request map[string]any, account *testsupport.Account) {
			request["userId"] = "not-a-uuid"
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			vault := newTestVault(t)
			account := testsupport.NewAccount(uniqueEmail("tamper"))
			vault.verifyEmail(t, account.Email)
			request := account.SignupRequest()
			tamper(request, account)
			response := vault.browser.Do("POST", "/vault/signup", request, nil)
			if response.Status != 400 {
				t.Fatalf("status %d (%s), want 400", response.Status, response.Raw)
			}
		})
	}
}

func TestSignupRejectsADuplicateEmail(t *testing.T) {
	vault := newTestVault(t)
	account := testsupport.NewAccount(uniqueEmail("dup"))
	vault.signUp(t, account)
	second := testsupport.NewAccount(account.Email)
	response := vault.browser.Do("POST", "/vault/signup/send-code", map[string]any{"email": second.Email}, nil)
	if response.Status != 409 {
		t.Fatalf("status %d, want 409", response.Status)
	}
}

func TestStateChangingRequestsNeedTheCSRFHeader(t *testing.T) {
	vault := newTestVault(t)
	response := vault.browser.Do("POST", "/vault/prelogin", map[string]any{"email": "a@example.com"}, map[string]string{"X-NW-Vault": ""})
	if response.Status != 403 {
		t.Fatalf("status %d, want 403", response.Status)
	}
	crossSite := vault.browser.Do("POST", "/vault/prelogin", map[string]any{"email": "a@example.com"}, map[string]string{"Origin": "https://evil.test"})
	if crossSite.Status != 403 {
		t.Fatalf("cross-origin status %d, want 403", crossSite.Status)
	}
}

func TestVaultPagesSendHardeningHeaders(t *testing.T) {
	vault := newTestVault(t)
	response := vault.browser.Do("GET", "/signin", nil, nil)
	policy := response.Header.Get("Content-Security-Policy")
	for _, want := range []string{"frame-ancestors 'none'", "script-src 'self' 'wasm-unsafe-eval'", "require-trusted-types-for 'script'", "default-src 'none'"} {
		if !contains(policy, want) {
			t.Errorf("CSP %q lacks %q", policy, want)
		}
	}
	if contains(policy, "unsafe-inline") {
		t.Errorf("CSP must not allow inline content: %q", policy)
	}
	if response.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("missing X-Frame-Options")
	}
	if contains(string(response.Raw), "<script>") {
		t.Error("page must not contain inline scripts")
	}
}

func contains(text, part string) bool {
	return strings.Contains(text, part)
}
