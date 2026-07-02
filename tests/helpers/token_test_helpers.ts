/**
 * Shared helpers for the live /oauth/token integration suite.
 *
 * Tests run against the real oauth server + SurrealDB + Redis (dev stack must
 * be up). Fixtures are namespaced `zztest-oauth-*`; every test file calls
 * setupFixtures()/teardownFixtures() in its own beforeAll/afterAll — bun runs
 * test files sequentially, so recreating the same fixture ids per file is safe.
 */
import { RedisClient } from "bun";
import { createRemoteJWKSet, jwtVerify } from "jose";

export const OAUTH_BASE = process.env.OAUTH_BASE_URL ?? "http://127.0.0.1:8080";
const SURREAL_BASE = process.env.SURREAL_HTTP_URL ?? "http://127.0.0.1:8000";
const SURREAL_AUTH = "Basic " + btoa("root:root");
const SURREAL_NS = process.env.SURREAL_NS ?? "neoworks";
const SURREAL_DB = process.env.SURREAL_DB ?? "auth";

export const redis = new RedisClient(process.env.REDIS_URL ?? "redis://127.0.0.1:6379");

// ── Fixtures ──────────────────────────────────────────────────────────────────

export const CONFIDENTIAL_CLIENT_ID = "zztest-oauth-confidential";
export const CONFIDENTIAL_CLIENT_SECRET = "zztest-confidential-secret";
export const PUBLIC_CLIENT_ID = "zztest-oauth-public";
export const TEST_USER_ID = "zztest-oauth-user";
export const REDIRECT_URI = "https://zztest.example/callback";
export const REGISTERED_SCOPES = ["storage:read", "storage:write"];

// ── SurrealDB ─────────────────────────────────────────────────────────────────

export async function surql(query: string): Promise<any[]> {
  const response = await fetch(`${SURREAL_BASE}/sql`, {
    method: "POST",
    headers: {
      Authorization: SURREAL_AUTH,
      Accept: "application/json",
      "surreal-ns": SURREAL_NS,
      "surreal-db": SURREAL_DB,
    },
    body: query,
  });
  const results = (await response.json()) as any[];
  for (const result of results) {
    if (result.status !== "OK") {
      throw new Error(`surql failed: ${JSON.stringify(result)}`);
    }
  }
  return results;
}

// ── Token endpoint ────────────────────────────────────────────────────────────

export type TokenCall = {
  status: number;
  body: any;
  headers: Headers;
};

export async function postToken(
  params: Record<string, string>,
  options: { basicAuth?: [string, string]; rawBody?: string; contentType?: string; method?: string } = {},
): Promise<TokenCall> {
  const headers: Record<string, string> = {};
  if (options.basicAuth) {
    headers.Authorization = "Basic " + btoa(`${options.basicAuth[0]}:${options.basicAuth[1]}`);
  }
  let body: string | undefined;
  if (options.rawBody !== undefined) {
    body = options.rawBody;
    headers["Content-Type"] = options.contentType ?? "text/plain";
  } else {
    body = new URLSearchParams(params).toString();
    headers["Content-Type"] = "application/x-www-form-urlencoded";
  }
  const response = await fetch(`${OAUTH_BASE}/oauth/token`, {
    method: options.method ?? "POST",
    headers,
    body: options.method === "GET" ? undefined : body,
  });
  const text = await response.text();
  let parsed: any = null;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = text;
  }
  return { status: response.status, body: parsed, headers: response.headers };
}

export function clientCredentialsParams(scope?: string): Record<string, string> {
  const params: Record<string, string> = {
    grant_type: "client_credentials",
    client_id: CONFIDENTIAL_CLIENT_ID,
    client_secret: CONFIDENTIAL_CLIENT_SECRET,
  };
  if (scope !== undefined) {
    params.scope = scope;
  }
  return params;
}

// ── PKCE ──────────────────────────────────────────────────────────────────────

export async function s256Challenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return Buffer.from(new Uint8Array(digest)).toString("base64url");
}

// ── Fixture planting ──────────────────────────────────────────────────────────

/**
 * Plants an auth code in Redis exactly as the Go cache store serializes it:
 * key `code:<code>`, JSON body of oauth.AuthCode. models.RecordID has no
 * custom JSON marshaler, so record ids are `{"Table": ..., "ID": ...}`.
 */
export async function plantAuthCode(overrides: {
  clientId?: string;
  redirectUri?: string;
  scopes?: string[];
  codeChallenge?: string;
  codeChallengeMethod?: string;
  expiresInSeconds?: number;
}): Promise<string> {
  const code = "zztest-code-" + crypto.randomUUID();
  const expiresAt = new Date(Date.now() + (overrides.expiresInSeconds ?? 60) * 1000);
  const payload = JSON.stringify({
    code,
    client_id: { Table: "client", ID: overrides.clientId ?? PUBLIC_CLIENT_ID },
    user_id: { Table: "user", ID: TEST_USER_ID },
    redirect_uri: overrides.redirectUri ?? REDIRECT_URI,
    scopes: overrides.scopes ?? ["storage:read"],
    code_challenge: overrides.codeChallenge ?? "",
    code_challenge_method: overrides.codeChallengeMethod ?? "",
    expires_at: expiresAt.toISOString(),
  });
  await redis.send("SET", [`code:${code}`, payload, "EX", "120"]);
  return code;
}

export async function plantRefreshToken(overrides: {
  revoked?: boolean;
  used?: boolean;
  expiresInSeconds?: number;
}): Promise<string> {
  const jti = "zztest-rt-" + crypto.randomUUID();
  const expiresAt = new Date(Date.now() + (overrides.expiresInSeconds ?? 3600) * 1000);
  await surql(`
    CREATE refresh_token CONTENT {
      id: refresh_token:\`${jti}\`,
      user: user:\`${TEST_USER_ID}\`,
      client: client:\`${CONFIDENTIAL_CLIENT_ID}\`,
      scopes: ["storage:read"],
      used: ${overrides.used ?? false},
      revoked: ${overrides.revoked ?? false},
      expires_at: d"${expiresAt.toISOString()}",
      created_at: d"${new Date().toISOString()}"
    };
  `);
  return jti;
}

/** Runs the full planted-code exchange for the public PKCE client. */
export async function exchangeFreshAuthCode(): Promise<TokenCall> {
  const verifier = "zztest-verifier-" + crypto.randomUUID();
  const code = await plantAuthCode({ codeChallenge: await s256Challenge(verifier), codeChallengeMethod: "S256" });
  return postToken({
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier,
  });
}

// ── Authorize flow ────────────────────────────────────────────────────────────
//
// The browser flow is driven directly over HTTP: GET /oauth/authorize issues a
// login challenge, then the SvelteKit-facing callbacks (/oauth/callback/login,
// /oauth/callback/consent) advance it to an auth code. The callbacks trust the
// user_id the front end resolves, so no real credential check is needed here.

// RFC 7636 §4 test vector: verifier for VALID_CODE_CHALLENGE.
export const VALID_CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
export const VALID_CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

export type AuthorizeResult = {
  status: number;
  location: string | null;
  loginChallenge: string | null;
  body: string;
};

export async function getAuthorize(params: Record<string, string>): Promise<AuthorizeResult> {
  const query = new URLSearchParams(params).toString();
  const response = await fetch(`${OAUTH_BASE}/oauth/authorize?${query}`, { redirect: "manual" });
  const location = response.headers.get("location");
  let loginChallenge: string | null = null;
  if (location) {
    loginChallenge = new URL(location, OAUTH_BASE).searchParams.get("login_challenge");
  }
  return { status: response.status, location, loginChallenge, body: await response.text() };
}

/** Default authorize parameters for the public PKCE test client. */
export function authorizeParams(overrides: Record<string, string> = {}): Record<string, string> {
  return {
    client_id: PUBLIC_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "storage:read",
    state: "zztest-state-xyz",
    code_challenge: VALID_CODE_CHALLENGE,
    code_challenge_method: "S256",
    ...overrides,
  };
}

async function postJSON(path: string, body: unknown): Promise<{ status: number; body: any }> {
  const response = await fetch(`${OAUTH_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  let parsed: any = text;
  try {
    parsed = JSON.parse(text);
  } catch {
    /* leave as text */
  }
  return { status: response.status, body: parsed };
}

export function postLoginCallback(loginChallenge: string, userId: string = TEST_USER_ID) {
  return postJSON("/oauth/callback/login", { login_challenge: loginChallenge, user_id: userId });
}

export function postConsentCallback(consentChallenge: string, accepted: boolean, scopes: string[]) {
  return postJSON("/oauth/callback/consent", { consent_challenge: consentChallenge, accepted, scopes });
}

/** Pulls a query parameter out of a `{ redirect: "<uri>" }` callback response. */
export function redirectParam(body: any, param: string): string | null {
  if (!body || typeof body.redirect !== "string") {
    return null;
  }
  return new URL(body.redirect, OAUTH_BASE).searchParams.get(param);
}

// ── JWT verification ──────────────────────────────────────────────────────────

let issuer = "";
const jwks = createRemoteJWKSet(new URL(`${OAUTH_BASE}/.well-known/jwks.json`));

export async function expectedIssuer(): Promise<string> {
  if (issuer === "") {
    const discovery = await fetch(`${OAUTH_BASE}/.well-known/openid-configuration`);
    if (discovery.status !== 200) {
      throw new Error(`oauth server not reachable at ${OAUTH_BASE}`);
    }
    issuer = ((await discovery.json()) as any).issuer;
  }
  return issuer;
}

export async function verifyAccessToken(token: string) {
  return jwtVerify(token, jwks, { issuer: await expectedIssuer(), algorithms: ["ES256"] });
}

// ── Setup / teardown ──────────────────────────────────────────────────────────

async function deleteFixtures() {
  await surql(`
    DELETE grant WHERE client = client:\`${CONFIDENTIAL_CLIENT_ID}\` OR client = client:\`${PUBLIC_CLIENT_ID}\`;
    DELETE refresh_token WHERE client = client:\`${CONFIDENTIAL_CLIENT_ID}\` OR client = client:\`${PUBLIC_CLIENT_ID}\`;
    DELETE client:\`${CONFIDENTIAL_CLIENT_ID}\`;
    DELETE client:\`${PUBLIC_CLIENT_ID}\`;
  `);
}

/** A per-test user id, so a persisted consent grant never leaks across tests. */
export function freshUserId(): string {
  return "zztest-oauth-user-" + crypto.randomUUID();
}

export async function setupFixtures() {
  await expectedIssuer();
  await deleteFixtures();
  const secretHash = Bun.password.hashSync(CONFIDENTIAL_CLIENT_SECRET, {
    algorithm: "bcrypt",
    cost: 4,
  });
  await surql(`
    CREATE client:\`${CONFIDENTIAL_CLIENT_ID}\` CONTENT {
      organization: organization:neoworks,
      secret_hash: "${secretHash}",
      redirect_uris: ["${REDIRECT_URI}"],
      scopes: ${JSON.stringify(REGISTERED_SCOPES)},
      auto_grant_scopes: false,
      public: false
    };
    CREATE client:\`${PUBLIC_CLIENT_ID}\` CONTENT {
      organization: organization:neoworks,
      secret_hash: NONE,
      redirect_uris: ["${REDIRECT_URI}"],
      scopes: ${JSON.stringify(REGISTERED_SCOPES)},
      auto_grant_scopes: false,
      public: true
    };
  `);
}

export async function teardownFixtures() {
  await deleteFixtures();
}
