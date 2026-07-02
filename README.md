# NeoWorks OAuth

OAuth 2.0 / OpenID Connect authorization server for the NeoWorks platform. It
implements the authorization-code (with PKCE), refresh-token, and
client-credentials grants, plus token introspection, revocation, JWKS, and the
login/consent callback flow.

## License

Source-available under the **PolyForm Shield License 1.0.0** — see
[LICENSE.md](./LICENSE.md). In short: you may use, modify, and self-host this
software for any purpose **except** building a product or service that competes
with NeoWorks or any NeoWorks product. There is no warranty.

## Building — read this first

This module is **not standalone**. `go.mod` contains:

```
replace github.com/neoworks/auth => ../api
```

It reuses shared packages (`oauth`, `storage/...`, `handlers/shared`, `crypto`,
`middleware`, …) from the `apps/api` module of the NeoWorks monorepo. It only
builds when checked out at `apps/oauth` inside that monorepo, with the `api`
module present as a sibling at `../api`.

This repository is therefore consumed as a **git submodule** of the monorepo,
not cloned and built on its own. Cloning it alone and running `go build` will
fail to resolve `github.com/neoworks/auth`.

## Local development

From the monorepo root, the dev stack (SurrealDB, Redis, Caddy, air-reloaded
Go services) brings this server up on `:8080`. Configuration is read from
`.env` (see `.env.example` for the expected keys: `KEY_PATH`, `REDIS_URL`,
`SURREAL_URL`, `SURREAL_NS`, `SURREAL_DB`, `ISSUER_URL`, `LOGIN_URL`, `PORT`).

## Tests

`tests/` holds live integration suites (Bun) that exercise the running server
end to end against real SurrealDB and Redis:

```
cd tests
bun install
bun test
```

The stack must be running. Fixtures are namespaced `zztest-*` and cleaned up
after each run.
