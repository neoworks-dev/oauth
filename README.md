# NeoWorks OAuth

Authorization server and account vault for NeoWorks. Two origins, one binary:

- **oauth origin** (`PORT`, default 8080): `/oauth/authorize` (hands the browser
  to the vault), `/oauth/token`, introspection, revocation, userinfo, JWKS,
  discovery, the stateless Google token proxy (`/google/token/*`) and the
  authenticator's handover delivery (`POST /vault/handover/{sessionId}`).
- **vault origin** (`VAULT_PORT`, default 8087, `https://vault.<BASE_DOMAIN>`):
  the account vault single-page app and its JSON API. It serves nothing else,
  cannot be framed and runs under a strict CSP with Trusted Types. The plaintext
  account master key exists only in this page's memory. Route
  `vault.<BASE_DOMAIN>` to `VAULT_PORT` in the reverse proxy.

`cmd/escrow` is the opt-in key escrow service: its own process, its own SurrealDB
namespace (`escrow`) and its own KMS key (a key file in development).

The service no longer reads any password: the browser derives `authKey` with
Argon2id and sends only that. See the contract in neoworks-dev/neoworks.dev#10.

## License

Source-available under the **PolyForm Shield License 1.0.0** — see
[LICENSE.md](./LICENSE.md).

## Building

`go.mod` still has `replace github.com/neoworks/auth => ../api` for the legacy
`handlers/fedcm`, `handlers/session`, `handlers/origins` and `middleware/sso`
packages, which no longer have a route and are awaiting a decision. Everything
else builds on its own (`internal/`).

## Development

```
go build ./... && go vet ./... && go test ./...
cd tests && bun install && bun test      # JS crypto, incl. the contract test vectors
cd tests && bunx playwright test          # real browser against `cmd/devstack`
```

`cmd/devstack` runs both origins, the escrow service, an in-memory SurrealDB and
an in-process Redis (needs the `surreal` binary); Playwright starts it itself.
Go tests start an in-memory SurrealDB too and skip when the binary is missing.
Set `NEOWORKS_MIGRATIONS=../api/sql/migrations` to run them against the real
schema instead of schemaless tables.

## Configuration

See `.env.example`. Notable: `VAULT_URL`, `API_URL`, `ISSUER_URL`,
`AUTHENTICATOR_CLIENT_ID`, `ESCROW_URL` + `ESCROW_SERVICE_TOKEN`,
`ESCROW_PUBLIC_KEY` is pinned in `handlers/vault/static/escrow-key.js`.
