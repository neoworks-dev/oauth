// Package vault serves the account vault: the interactive pages and the JSON
// endpoints behind them. It runs on its own origin and is the only place where
// the browser holds the plaintext account master key.
package vault

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/oauth/internal/cache"
	"github.com/neoworks/oauth/internal/mail"
	"github.com/neoworks/oauth/internal/store"
	"github.com/neoworks/oauth/internal/tokens"
)

const maxBodyBytes = 1 << 20

// Store is the database slice the vault needs.
type Store interface {
	GetClient(ctx context.Context, clientID string) (*store.Client, error)
	GetUserByEmail(ctx context.Context, email string) (*store.User, error)
	GetUserByID(ctx context.Context, userID string) (*store.User, error)
	GetKeyBundle(ctx context.Context, userID string) (*store.KeyBundle, error)
	CreateAccount(ctx context.Context, account store.NewAccount) error
	ChangePassword(ctx context.Context, change store.PasswordChange) error
	RotateBundle(ctx context.Context, rotation store.Rotation) error
	SetEscrowEnabled(ctx context.Context, userID string, enabled bool) error
	RegisterDevice(ctx context.Context, userID, deviceID, name, kind string) error
	IsDeviceActive(ctx context.Context, userID, deviceID string) (bool, error)
	GetInstall(ctx context.Context, installID string) (*store.Install, error)
	SaveInstallConsent(ctx context.Context, consent store.InstallConsent) error
	ListStructure(ctx context.Context, userID string) ([]store.Node, error)
	ListOwnerGrants(ctx context.Context, userID string) ([]store.AccessGrant, error)
	GetNodeOwnerships(ctx context.Context, nodeIDs []string) ([]store.NodeOwnership, error)
}

// State is the Redis slice the vault needs.
type State interface {
	SaveVaultSession(ctx context.Context, token string, session cache.VaultSession) error
	GetVaultSession(ctx context.Context, token string) (*cache.VaultSession, error)
	DeleteVaultSession(ctx context.Context, token string) error
	GetLoginChallenge(ctx context.Context, challengeID string) (*cache.LoginChallenge, error)
	TakeLoginChallenge(ctx context.Context, challengeID string) (*cache.LoginChallenge, error)
	SaveAuthCode(ctx context.Context, code cache.AuthCode) error
	SaveVerificationCode(ctx context.Context, purpose, email, code string) error
	GetVerificationCode(ctx context.Context, purpose, email string) (string, error)
	DeleteVerificationCode(ctx context.Context, purpose, email string) error
	MarkEmailVerified(ctx context.Context, email string) error
	ConsumeEmailVerified(ctx context.Context, email string) (bool, error)
	SaveResetToken(ctx context.Context, token, email string) error
	ConsumeResetToken(ctx context.Context, token string) (string, error)
	CountWithin(ctx context.Context, key string, window time.Duration) (int64, error)
	CreateHandover(ctx context.Context, sessionID string, session cache.HandoverSession) (bool, error)
	GetHandover(ctx context.Context, sessionID string) (*cache.HandoverSession, error)
	DeliverHandover(ctx context.Context, sessionID string, session cache.HandoverSession) error
	TakeHandover(ctx context.Context, sessionID string) (*cache.HandoverSession, error)
	IsRevoked(ctx context.Context, tokenID string) (bool, error)
}

// Config holds the deployment settings of the vault origin.
type Config struct {
	VaultURL       string
	APIURL         string
	OAuthURL       string
	Debug          bool
	SecureCookies  bool
	PreloginSecret []byte
}

type Server struct {
	config Config
	store  Store
	state  State
	issuer *tokens.Issuer
	mailer mail.Sender
	escrow Escrow
}

func NewServer(config Config, vaultStore Store, state State, issuer *tokens.Issuer, mailer mail.Sender, escrow Escrow) *Server {
	return &Server{config: config, store: vaultStore, state: state, issuer: issuer, mailer: mailer, escrow: escrow}
}

// Router returns the handler for the vault origin.
func (server *Server) Router() http.Handler {
	router := chi.NewRouter()
	router.Use(securityHeaders(server.config))
	server.registerPages(router)
	router.Route("/vault", func(api chi.Router) {
		api.Use(requireSameOriginJSON(server.config.VaultURL))
		server.registerAPI(api)
	})
	return router
}

// HandoverRouter exposes only the authenticator side of the handover, for the
// oauth origin.
func (server *Server) HandoverRouter(router chi.Router) {
	router.Post("/vault/handover/{sessionID}", server.handleHandoverDeliver)
}

func (server *Server) registerAPI(api chi.Router) {
	api.Post("/prelogin", server.handlePrelogin)
	api.Post("/login", server.handleLogin)
	api.Post("/logout", server.handleLogout)
	api.Get("/session", server.handleSession)
	api.Get("/challenge", server.handleChallenge)
	api.Post("/signup/send-code", server.handleSignupSendCode)
	api.Post("/signup/verify-code", server.handleSignupVerifyCode)
	api.Post("/signup", server.handleSignup)
	api.Post("/forgot/send-code", server.handleForgotSendCode)
	api.Post("/forgot/verify-code", server.handleForgotVerifyCode)
	api.Post("/forgot/reset", server.handleForgotReset)
	api.Post("/handover/{sessionID}", server.handleHandoverDeliver)
	api.Group(func(authenticated chi.Router) {
		authenticated.Use(server.requireSession)
		server.registerAuthenticated(authenticated)
	})
}

func (server *Server) registerAuthenticated(api chi.Router) {
	api.Get("/bundle", server.handleBundle)
	api.Post("/token", server.handleToken)
	api.Get("/tree", server.handleTree)
	api.Post("/consent", server.handleConsent)
	api.Post("/password", server.handleChangePassword)
	api.Post("/rotate", server.handleRotate)
	api.Post("/handover", server.handleHandoverCreate)
	api.Get("/handover/{sessionID}", server.handleHandoverPoll)
	api.Get("/qr.png", server.handleQR)
	server.registerEscrowRoutes(api)
}

func readJSON(request *http.Request, destination any) error {
	body := http.MaxBytesReader(nil, request.Body, maxBodyBytes)
	defer body.Close()
	payload, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, destination)
}

func writeJSON(response http.ResponseWriter, status int, body any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(body)
}

func writeError(response http.ResponseWriter, status int, code string) {
	writeJSON(response, status, map[string]string{"error": code})
}
