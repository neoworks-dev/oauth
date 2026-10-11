package ratelimit

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/neoworks/oauth/internal/store"
)

type fakeState struct {
	counts    map[string]int64
	remaining time.Duration
	failing   bool
	recorded  []bool
}

func newFakeState() *fakeState {
	return &fakeState{counts: map[string]int64{}, remaining: 1500 * time.Millisecond}
}

func (state *fakeState) Hit(_ context.Context, key string, _ time.Duration) (int64, time.Duration, error) {
	if state.failing {
		return 0, 0, errors.New("redis down")
	}
	state.counts[key]++
	return state.counts[key], state.remaining, nil
}

func (state *fakeState) RecordUsage(_ context.Context, _ string, limited bool) error {
	state.recorded = append(state.recorded, limited)
	return nil
}

type fakeClients map[string]*store.Client

func (clients fakeClients) GetClient(_ context.Context, clientID string) (*store.Client, error) {
	client, found := clients[clientID]
	if !found {
		return nil, errors.New("not found")
	}
	return client, nil
}

var testLimits = map[Bucket]Limit{BucketToken: {PerClient: 4, PerIPClient: 2, PerIP: 3}}

func newTestLimiter(state *fakeState, clients fakeClients) http.Handler {
	limiter := &Limiter{state: state, clients: clients, limits: testLimits}
	ok := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	})
	return limiter.Middleware(BucketToken, QueryClientID)(ok)
}

func call(handler http.Handler, clientID string, remoteAddr string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "/oauth/token?client_id="+clientID, nil)
	request.RemoteAddr = remoteAddr
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func countAllowed(handler http.Handler, clientID string, remoteAddr string, attempts int) int {
	allowed := 0
	for attempt := 0; attempt < attempts; attempt++ {
		if call(handler, clientID, remoteAddr).Code == http.StatusOK {
			allowed++
		}
	}
	return allowed
}

func TestMultiplierFor(t *testing.T) {
	override := 0.5
	cases := []struct {
		name   string
		client store.Client
		want   float64
	}{
		{"default", store.Client{}, MultiplierDefault},
		{"verified", store.Client{Verified: true}, MultiplierVerified},
		{"approved", store.Client{ReviewStatus: "approved"}, MultiplierApproved},
		{"approved and verified", store.Client{ReviewStatus: "approved", Verified: true}, MultiplierBoth},
		{"first party", store.Client{FirstParty: true}, MultiplierOfficial},
		{"operator override wins", store.Client{FirstParty: true, RateLimitMultiplier: &override}, 0.5},
		{"pending review earns nothing", store.Client{ReviewStatus: "pending"}, MultiplierDefault},
	}
	for _, testCase := range cases {
		if got := MultiplierFor(&testCase.client); got != testCase.want {
			t.Errorf("%s: MultiplierFor = %v, want %v", testCase.name, got, testCase.want)
		}
	}
}

func TestScaledNeverDropsBelowOne(t *testing.T) {
	if got := scaled(10, 0.01); got != 1 {
		t.Fatalf("scaled(10, 0.01) = %d, want 1", got)
	}
	if got := scaled(10, 2.5); got != 25 {
		t.Fatalf("scaled(10, 2.5) = %d, want 25", got)
	}
}

func TestUnknownClientsAreHeldToThePerIPLimitAndRecordNoUsage(t *testing.T) {
	state := newFakeState()
	handler := newTestLimiter(state, fakeClients{})
	if allowed := countAllowed(handler, "nobody", "192.0.2.1:4000", 10); allowed != 3 {
		t.Fatalf("unknown client calls before the limit: %d want 3", allowed)
	}
	if len(state.recorded) != 0 {
		t.Fatalf("usage recorded for an unknown client: %v", state.recorded)
	}
}

func TestPerIPClientLimitAppliesPerAddress(t *testing.T) {
	state := newFakeState()
	handler := newTestLimiter(state, fakeClients{"app": {}})
	if allowed := countAllowed(handler, "app", "192.0.2.1:4000", 2); allowed != 2 {
		t.Fatalf("first address: %d want 2", allowed)
	}
	if call(handler, "app", "192.0.2.1:4000").Code != http.StatusTooManyRequests {
		t.Fatal("a third call from the first address passed the per-IP-client limit")
	}
	if allowed := countAllowed(handler, "app", "192.0.2.2:4000", 1); allowed != 1 {
		t.Fatalf("second address: %d want 1 (client limit 4 not yet reached)", allowed)
	}
	if allowed := countAllowed(handler, "app", "192.0.2.3:4000", 2); allowed != 0 {
		t.Fatalf("third address: %d want 0 once the client limit is spent", allowed)
	}
}

func TestMultiplierRaisesTheClientLimits(t *testing.T) {
	clients := fakeClients{"plain": {}, "trusted": {ReviewStatus: "approved", Verified: true}}
	if allowed := countAllowed(newTestLimiter(newFakeState(), clients), "plain", "192.0.2.1:4000", 20); allowed != 2 {
		t.Fatalf("default client from one address: %d want 2", allowed)
	}
	if allowed := countAllowed(newTestLimiter(newFakeState(), clients), "trusted", "192.0.2.1:4000", 20); allowed != 3 {
		t.Fatalf("trusted client from one address: %d want 3 (per-IP limit is not scaled)", allowed)
	}
}

func TestRefusalCarriesRetryAfterRoundedUp(t *testing.T) {
	state := newFakeState()
	handler := newTestLimiter(state, fakeClients{})
	countAllowed(handler, "nobody", "192.0.2.1:4000", 3)
	refused := call(handler, "nobody", "192.0.2.1:4000")
	if refused.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d want 429", refused.Code)
	}
	if got := refused.Header().Get("Retry-After"); got != "2" {
		t.Fatalf("Retry-After %q want 2", got)
	}
	if !strings.Contains(refused.Body.String(), `"error":"rate_limited"`) {
		t.Fatalf("body %s", refused.Body.String())
	}
}

func TestRetryAfterIsAtLeastOneSecond(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeLimited(recorder, 0)
	if got := recorder.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After %q want 1", got)
	}
}

func TestLimitedCallsAreRecordedAsLimited(t *testing.T) {
	state := newFakeState()
	handler := newTestLimiter(state, fakeClients{"app": {}})
	countAllowed(handler, "app", "192.0.2.1:4000", 3)
	want := []bool{false, false, true}
	if len(state.recorded) != len(want) {
		t.Fatalf("recorded %v want %v", state.recorded, want)
	}
	for index := range want {
		if state.recorded[index] != want[index] {
			t.Fatalf("recorded %v want %v", state.recorded, want)
		}
	}
}

func TestCallsPassWhenTheCounterFails(t *testing.T) {
	state := newFakeState()
	state.failing = true
	handler := newTestLimiter(state, fakeClients{"app": {}})
	if allowed := countAllowed(handler, "app", "192.0.2.1:4000", 10); allowed != 10 {
		t.Fatalf("calls with Redis down: %d want 10", allowed)
	}
}

func TestFormClientIDReadsTheFormThenBasicAuth(t *testing.T) {
	form := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(url.Values{"client_id": {"from-form"}}.Encode()))
	form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if got := FormClientID(form); got != "from-form" {
		t.Fatalf("form client %q", got)
	}
	if form.PostFormValue("client_id") != "from-form" {
		t.Fatal("the form is no longer readable by the handler")
	}

	basic := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("grant_type=client_credentials"))
	basic.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	basic.SetBasicAuth("from-basic", "secret")
	if got := FormClientID(basic); got != "from-basic" {
		t.Fatalf("basic client %q", got)
	}
}
