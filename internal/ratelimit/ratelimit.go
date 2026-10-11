// Package ratelimit limits the machine endpoints of the oauth origin: the token
// endpoint and the authorization endpoint. Counters live in Redis, shared with
// the api, so every instance of both enforces the same limits and the usage
// page of an app counts the calls of both.
package ratelimit

import (
	"context"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/neoworks/oauth/internal/store"
)

// Window is the length of the counting window of every limit.
const Window = time.Minute

// Bucket is a kind of call that is limited on its own.
type Bucket string

const (
	BucketToken     Bucket = "token"
	BucketAuthorize Bucket = "authorize"
)

// Limit is the calls allowed per Window: for a client as a whole, for one IP
// calling for that client (the user is not known before the token exists), and
// for one IP across all clients, which also covers callers with unknown clients.
type Limit struct {
	PerClient   int
	PerIPClient int
	PerIP       int
}

// DefaultLimits are the limits of a client that has not been reviewed or verified.
var DefaultLimits = map[Bucket]Limit{
	BucketToken:     {PerClient: 600, PerIPClient: 60, PerIP: 120},
	BucketAuthorize: {PerClient: 600, PerIPClient: 60, PerIP: 120},
}

// Multipliers scale the limits of a client by its standing.
const (
	MultiplierDefault  = 1.0
	MultiplierVerified = 2.0
	MultiplierApproved = 3.0
	MultiplierBoth     = 4.0
	MultiplierOfficial = 20.0
)

// MultiplierFor is the factor applied to the limits of a client: the one an
// operator set, otherwise what its first-party, verified and reviewed standing
// earns. It matches the api's.
func MultiplierFor(client *store.Client) float64 {
	if client.RateLimitMultiplier != nil {
		return *client.RateLimitMultiplier
	}
	if client.FirstParty {
		return MultiplierOfficial
	}
	approved := client.ReviewStatus == "approved"
	switch {
	case approved && client.Verified:
		return MultiplierBoth
	case approved:
		return MultiplierApproved
	case client.Verified:
		return MultiplierVerified
	}
	return MultiplierDefault
}

// State is the Redis slice the limiter needs.
type State interface {
	Hit(ctx context.Context, key string, window time.Duration) (int64, time.Duration, error)
	RecordUsage(ctx context.Context, clientID string, limited bool) error
}

// Clients reads clients.
type Clients interface {
	GetClient(ctx context.Context, clientID string) (*store.Client, error)
}

// Limiter enforces the limits. When Redis fails it lets calls through.
type Limiter struct {
	state   State
	clients Clients
	limits  map[Bucket]Limit
}

func New(state State, clients Clients) *Limiter {
	return &Limiter{state: state, clients: clients, limits: DefaultLimits}
}

// ClientIDFunc names the client a request is made for; empty when it names none.
type ClientIDFunc func(request *http.Request) string

// Middleware limits the requests of the bucket. Callers naming no known client
// are held to the per-IP limit alone.
func (limiter *Limiter) Middleware(bucket Bucket, clientOf ClientIDFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if wait := limiter.check(request, bucket, clientOf(request)); wait > 0 {
				writeLimited(response, wait)
				return
			}
			next.ServeHTTP(response, request)
		})
	}
}

// check counts the request and returns how long to wait when it is over a limit.
func (limiter *Limiter) check(request *http.Request, bucket Bucket, clientID string) time.Duration {
	ctx := request.Context()
	limit := limiter.limits[bucket]
	address := clientIP(request)
	if wait := limiter.hit(ctx, "rl:"+string(bucket)+":ip:"+address, limit.PerIP); wait > 0 {
		return wait
	}
	client := limiter.knownClient(ctx, clientID)
	if client == nil {
		return 0
	}
	multiplier := MultiplierFor(client)
	wait := limiter.hit(ctx, "rl:"+string(bucket)+":client:"+clientID, scaled(limit.PerClient, multiplier))
	if wait == 0 {
		wait = limiter.hit(ctx, "rl:"+string(bucket)+":ipclient:"+clientID+":"+address, scaled(limit.PerIPClient, multiplier))
	}
	limiter.record(ctx, clientID, wait > 0)
	return wait
}

func (limiter *Limiter) knownClient(ctx context.Context, clientID string) *store.Client {
	if clientID == "" {
		return nil
	}
	client, err := limiter.clients.GetClient(ctx, clientID)
	if err != nil {
		return nil
	}
	return client
}

func (limiter *Limiter) hit(ctx context.Context, key string, limit int) time.Duration {
	count, remaining, err := limiter.state.Hit(ctx, key, Window)
	if err != nil {
		slog.Warn("rate limit counter unavailable", "error", err)
		return 0
	}
	if count <= int64(limit) {
		return 0
	}
	return remaining
}

func (limiter *Limiter) record(ctx context.Context, clientID string, limited bool) {
	if err := limiter.state.RecordUsage(ctx, clientID, limited); err != nil {
		slog.Warn("record client usage", "error", err)
	}
}

func scaled(limit int, multiplier float64) int {
	scaledLimit := int(float64(limit) * multiplier)
	if scaledLimit < 1 {
		return 1
	}
	return scaledLimit
}

func clientIP(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return request.RemoteAddr
	}
	return host
}

func writeLimited(response http.ResponseWriter, wait time.Duration) {
	seconds := int(math.Ceil(wait.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	response.Header().Set("Retry-After", strconv.Itoa(seconds))
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusTooManyRequests)
	_, _ = response.Write([]byte(`{"error":"rate_limited","error_description":"too many requests; retry after the delay","retry_after":` + strconv.Itoa(seconds) + `}`))
}

// QueryClientID names the client of an authorization request.
func QueryClientID(request *http.Request) string {
	return request.URL.Query().Get("client_id")
}

// FormClientID names the client of a token request: the client_id form field,
// else the user name of HTTP Basic authentication. Reading the form leaves it
// available to the handler.
func FormClientID(request *http.Request) string {
	if err := request.ParseForm(); err != nil {
		return ""
	}
	if clientID := request.FormValue("client_id"); clientID != "" {
		return clientID
	}
	clientID, _, _ := request.BasicAuth()
	return clientID
}
