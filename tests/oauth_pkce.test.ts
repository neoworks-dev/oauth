import {
  describe,
  test,
  expect,
  beforeAll,
  afterAll,
  beforeEach,
} from "bun:test";
import { generateKeyPair, SignJWT, jwtVerify } from "jose";
import type { KeyLike } from "jose";

// ── Types ─────────────────────────────────────────────────────────────────────

type Client = {
  id: string;
  redirectURIs: string[];
  scopes: string[];
  autoGrant: boolean;
};

type User = {
  id: string;
  email: string;
  password: string; // plaintext — test only
};

type LoginChallenge = {
  id: string;
  clientId: string;
  scopes: string[];
  redirectURI: string;
  state: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  expiresAt: Date;
};

type AuthCode = {
  code: string;
  clientId: string;
  userId: string;
  redirectURI: string;
  scopes: string[];
  codeChallenge: string;
  codeChallengeMethod: string;
  expiresAt: Date;
};

type RefreshToken = {
  id: string;
  userId: string;
  clientId: string;
  scopes: string[];
  expiresAt: Date;
  used: boolean;
  revoked: boolean;
};

// ── Static fixtures ───────────────────────────────────────────────────────────

const CLIENTS = new Map<string, Client>([
  [
    "auto-client",
    {
      id: "auto-client",
      redirectURIs: ["https://app.example.com/callback"],
      scopes: ["openid", "profile", "email"],
      autoGrant: true,
    },
  ],
  [
    "consent-client",
    {
      id: "consent-client",
      redirectURIs: ["https://app.example.com/callback"],
      scopes: ["openid", "profile"],
      autoGrant: false,
    },
  ],
]);

const USERS = new Map<string, User>([
  [
    "alice@example.com",
    { id: "user-alice", email: "alice@example.com", password: "password123" },
  ],
]);

// ── Per-test mutable state ────────────────────────────────────────────────────

let loginChallenges: Map<string, LoginChallenge>;
let authCodes: Map<string, AuthCode>;
let refreshTokens: Map<string, RefreshToken>;
let loginSessions: Map<string, string>; // sessionToken → userId

function resetStore() {
  loginChallenges = new Map();
  authCodes = new Map();
  refreshTokens = new Map();
  loginSessions = new Map();
}

// ── PKCE ─────────────────────────────────────────────────────────────────────

export function generateVerifier(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

export async function computeChallenge(verifier: string): Promise<string> {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

async function pkceValid(
  verifier: string,
  challenge: string,
  method: string,
): Promise<boolean> {
  if (method !== "S256") return false;
  return (await computeChallenge(verifier)) === challenge;
}

// ── JWT ───────────────────────────────────────────────────────────────────────

let privateKey: KeyLike;
let publicKey: KeyLike;

async function issueAccessToken(
  userId: string,
  clientId: string,
  scopes: string[],
): Promise<string> {
  return new SignJWT({ client_id: clientId, scope: scopes })
    .setProtectedHeader({ alg: "ES256" })
    .setSubject(userId)
    .setIssuedAt()
    .setExpirationTime("15m")
    .setIssuer("https://auth.test")
    .setJti(crypto.randomUUID())
    .sign(privateKey);
}

// ── Mock OAuth server ─────────────────────────────────────────────────────────

async function handleRequest(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const { method, pathname } = { method: req.method, pathname: url.pathname };

  if (method === "GET" && pathname === "/oauth/authorize")
    return authorize(req, url);
  if (method === "POST" && pathname === "/auth/login") return login(req);
  if (method === "GET" && pathname === "/oauth/consent")
    return consentGet(req, url);
  if (method === "POST" && pathname === "/oauth/consent")
    return consentPost(req);
  if (method === "POST" && pathname === "/oauth/token") return token(req);

  return new Response("not found", { status: 404 });
}

function authorize(req: Request, url: URL): Response {
  const origin = new URL(req.url).origin;
  const p = url.searchParams;
  const clientId = p.get("client_id") ?? "";
  const redirectURI = p.get("redirect_uri") ?? "";
  const responseType = p.get("response_type") ?? "";
  const scope = p.get("scope") ?? "";
  const state = p.get("state") ?? "";
  const codeChallenge = p.get("code_challenge") ?? "";
  const codeChallengeMethod = p.get("code_challenge_method") ?? "";

  if (responseType !== "code")
    return errRedirect(redirectURI, state, "unsupported_response_type");
  if (!codeChallenge)
    return errRedirect(
      redirectURI,
      state,
      "invalid_request",
      "code_challenge required",
    );
  if (codeChallengeMethod !== "S256")
    return errRedirect(
      redirectURI,
      state,
      "invalid_request",
      "only S256 supported",
    );

  if (!clientId) return new Response("missing client_id", { status: 400 });

  const client = CLIENTS.get(clientId);
  if (!client) return new Response("invalid client", { status: 401 });
  if (!client.redirectURIs.includes(redirectURI))
    return new Response("invalid redirect_uri", { status: 400 });

  const requested = scope.split(" ").filter(Boolean);
  if (!requested.every((s) => client.scopes.includes(s)))
    return errRedirect(redirectURI, state, "invalid_scope");

  const challenge: LoginChallenge = {
    id: crypto.randomUUID(),
    clientId,
    scopes: requested,
    redirectURI,
    state,
    codeChallenge,
    codeChallengeMethod,
    expiresAt: new Date(Date.now() + 10 * 60_000),
  };
  loginChallenges.set(challenge.id, challenge);

  const dest = new URL(`${origin}/auth/login`);
  dest.searchParams.set("login_challenge", challenge.id);
  return Response.redirect(dest.toString(), 302);
}

async function login(req: Request): Promise<Response> {
  const origin = new URL(req.url).origin;
  const form = await req.formData();
  const email = (form.get("email") as string) ?? "";
  const password = (form.get("password") as string) ?? "";
  const loginChallengeId = (form.get("login_challenge") as string) ?? "";

  const user = USERS.get(email);
  if (!user || user.password !== password)
    return new Response("invalid credentials", { status: 401 });

  const challenge = loginChallenges.get(loginChallengeId);
  if (!challenge || challenge.expiresAt < new Date())
    return new Response("invalid login challenge", { status: 400 });

  const client = CLIENTS.get(challenge.clientId);
  if (!client) return new Response("invalid client", { status: 401 });

  if (client.autoGrant) {
    loginChallenges.delete(loginChallengeId);
    return codeRedirect(user.id, challenge);
  }

  // Non-auto-grant: issue a short-lived session cookie and go to consent
  const sessionToken = crypto.randomUUID();
  loginSessions.set(sessionToken, user.id);

  const dest = new URL(`${origin}/oauth/consent`);
  dest.searchParams.set("login_challenge", challenge.id);

  return new Response(null, {
    status: 302,
    headers: {
      Location: dest.toString(),
      "Set-Cookie": `login_session=${sessionToken}; HttpOnly; Path=/oauth`,
    },
  });
}

function consentGet(req: Request, url: URL): Response {
  const loginChallengeId = url.searchParams.get("login_challenge") ?? "";
  const sessionToken = getCookie(req, "login_session");
  if (!sessionToken || !loginSessions.has(sessionToken))
    return new Response("unauthorized", { status: 401 });
  if (!loginChallenges.has(loginChallengeId))
    return new Response("invalid challenge", { status: 400 });
  return new Response(
    `<html><body>consent for ${loginChallengeId}</body></html>`,
    {
      headers: { "Content-Type": "text/html" },
    },
  );
}

async function consentPost(req: Request): Promise<Response> {
  const form = await req.formData();
  const loginChallengeId = (form.get("login_challenge") as string) ?? "";
  const action = (form.get("action") as string) ?? "";
  const sessionToken = getCookie(req, "login_session");

  const userId = sessionToken ? loginSessions.get(sessionToken) : undefined;
  if (!userId) return new Response("unauthorized", { status: 401 });

  const challenge = loginChallenges.get(loginChallengeId);
  if (!challenge) return new Response("invalid challenge", { status: 400 });

  loginChallenges.delete(loginChallengeId);
  if (sessionToken) loginSessions.delete(sessionToken);

  if (action !== "allow") {
    const dest = new URL(challenge.redirectURI);
    dest.searchParams.set("error", "access_denied");
    dest.searchParams.set("state", challenge.state);
    return Response.redirect(dest.toString(), 302);
  }

  return codeRedirect(userId, challenge);
}

async function token(req: Request): Promise<Response> {
  const form = await req.formData();
  const grantType = form.get("grant_type") as string;

  if (grantType === "authorization_code") return authCodeGrant(form);
  if (grantType === "refresh_token") return refreshGrant(form);
  return tokenErr("unsupported_grant_type", 400);
}

async function authCodeGrant(form: FormData): Promise<Response> {
  const code = (form.get("code") as string) ?? "";
  const redirectURI = (form.get("redirect_uri") as string) ?? "";
  const verifier = (form.get("code_verifier") as string) ?? "";

  if (!code || !redirectURI || !verifier) return tokenErr("invalid_grant", 400);

  const ac = authCodes.get(code);
  if (!ac) return tokenErr("invalid_grant", 400);
  authCodes.delete(code); // single-use

  if (ac.expiresAt < new Date()) return tokenErr("invalid_grant", 400);
  if (ac.redirectURI !== redirectURI) return tokenErr("invalid_grant", 400);
  if (!(await pkceValid(verifier, ac.codeChallenge, ac.codeChallengeMethod)))
    return tokenErr("invalid_grant", 400);

  const accessToken = await issueAccessToken(ac.userId, ac.clientId, ac.scopes);
  const rt: RefreshToken = {
    id: crypto.randomUUID(),
    userId: ac.userId,
    clientId: ac.clientId,
    scopes: ac.scopes,
    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60_000),
    used: false,
    revoked: false,
  };
  refreshTokens.set(rt.id, rt);

  return Response.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 900,
    refresh_token: rt.id,
    scope: ac.scopes.join(" "),
  });
}

async function refreshGrant(form: FormData): Promise<Response> {
  const rawToken = (form.get("refresh_token") as string) ?? "";
  if (!rawToken) return tokenErr("invalid_grant", 400);

  const rt = refreshTokens.get(rawToken);
  if (!rt) return tokenErr("invalid_grant", 400);

  if (rt.used || rt.revoked) {
    // Potential replay attack — revoke the entire grant.
    for (const [id, t] of refreshTokens) {
      if (t.userId === rt.userId && t.clientId === rt.clientId) {
        t.revoked = true;
        refreshTokens.delete(id);
      }
    }
    return tokenErr("invalid_grant", 400);
  }

  if (rt.expiresAt < new Date()) return tokenErr("invalid_grant", 400);

  rt.used = true;

  const accessToken = await issueAccessToken(rt.userId, rt.clientId, rt.scopes);
  const newRefreshToken: RefreshToken = {
    id: crypto.randomUUID(),
    userId: rt.userId,
    clientId: rt.clientId,
    scopes: rt.scopes,
    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60_000),
    used: false,
    revoked: false,
  };
  refreshTokens.set(newRefreshToken.id, newRefreshToken);

  return Response.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 900,
    refresh_token: newRefreshToken.id,
    scope: rt.scopes.join(" "),
  });
}

// ── Server helpers ────────────────────────────────────────────────────────────

function codeRedirect(userId: string, challenge: LoginChallenge): Response {
  const code = crypto.randomUUID();
  authCodes.set(code, {
    code,
    clientId: challenge.clientId,
    userId,
    redirectURI: challenge.redirectURI,
    scopes: challenge.scopes,
    codeChallenge: challenge.codeChallenge,
    codeChallengeMethod: challenge.codeChallengeMethod,
    expiresAt: new Date(Date.now() + 10 * 60_000),
  });
  const dest = new URL(challenge.redirectURI);
  dest.searchParams.set("code", code);
  dest.searchParams.set("state", challenge.state);
  return Response.redirect(dest.toString(), 302);
}

function errRedirect(
  redirectURI: string,
  state: string,
  error: string,
  description?: string,
): Response {
  if (!redirectURI) return new Response(error, { status: 400 });
  const dest = new URL(redirectURI);
  dest.searchParams.set("error", error);
  if (description) dest.searchParams.set("error_description", description);
  dest.searchParams.set("state", state);
  return Response.redirect(dest.toString(), 302);
}

function tokenErr(error: string, status: number): Response {
  return Response.json({ error }, { status });
}

function getCookie(req: Request, name: string): string | undefined {
  const header = req.headers.get("cookie") ?? "";
  for (const part of header.split(";")) {
    const [k, v] = part.trim().split("=");
    if (k === name) return v;
  }
  return undefined;
}

// ── Setup ─────────────────────────────────────────────────────────────────────

let server: ReturnType<typeof Bun.serve>;
let BASE: string;

beforeAll(async () => {
  ({ privateKey, publicKey } = await generateKeyPair("ES256"));
  resetStore();
  server = Bun.serve({ port: 0, fetch: handleRequest });
  BASE = `http://localhost:${server.port}`;
});

afterAll(() => server.stop(true));

beforeEach(() => resetStore());

// ── Test HTTP helpers ─────────────────────────────────────────────────────────

async function doAuthorize(opts: {
  clientId?: string;
  scope?: string;
  state?: string;
  challenge: string;
  method?: string;
  redirectURI?: string;
}): Promise<Response> {
  const url = new URL(`${BASE}/oauth/authorize`);
  url.searchParams.set("client_id", opts.clientId ?? "auto-client");
  url.searchParams.set(
    "redirect_uri",
    opts.redirectURI ?? "https://app.example.com/callback",
  );
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", opts.scope ?? "openid profile");
  url.searchParams.set("state", opts.state ?? "test-state");
  url.searchParams.set("code_challenge", opts.challenge);
  url.searchParams.set("code_challenge_method", opts.method ?? "S256");
  return fetch(url.toString(), { redirect: "manual" });
}

async function doLogin(
  loginChallenge: string,
  email = "alice@example.com",
  password = "password123",
): Promise<Response> {
  return fetch(`${BASE}/auth/login`, {
    method: "POST",
    redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      email,
      password,
      login_challenge: loginChallenge,
    }),
  });
}

async function doTokenExchange(
  code: string,
  verifier: string,
  redirectURI = "https://app.example.com/callback",
  clientId = "auto-client",
): Promise<Response> {
  return fetch(`${BASE}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectURI,
      client_id: clientId,
      code_verifier: verifier,
    }),
  });
}

async function doRefresh(refreshToken: string): Promise<Response> {
  return fetch(`${BASE}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    }),
  });
}

function locationOf(resp: Response): URL {
  return new URL(resp.headers.get("location")!);
}

/** Runs the full auto-grant PKCE flow and returns tokens + the verifier used. */
async function fullAutoGrantFlow(
  clientId = "auto-client",
  scope = "openid profile",
  state = "test-state",
): Promise<{ tokens: Record<string, any>; verifier: string }> {
  const verifier = generateVerifier();
  const challenge = await computeChallenge(verifier);

  const authResp = await doAuthorize({ clientId, scope, state, challenge });
  const loginChallenge =
    locationOf(authResp).searchParams.get("login_challenge")!;

  const loginResp = await doLogin(loginChallenge);
  const code = locationOf(loginResp).searchParams.get("code")!;

  const tokenResp = await doTokenExchange(code, verifier);
  return { tokens: await tokenResp.json(), verifier };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("OAuth PKCE", () => {
  describe("PKCE crypto primitives", () => {
    test("verifier → challenge → verify round-trip", async () => {
      const verifier = generateVerifier();
      const challenge = await computeChallenge(verifier);
      expect(await pkceValid(verifier, challenge, "S256")).toBe(true);
    });

    test("tampered verifier fails", async () => {
      const challenge = await computeChallenge("correct-verifier");
      expect(await pkceValid("wrong-verifier", challenge, "S256")).toBe(false);
    });

    test("plain method always fails (rejected per spec)", async () => {
      const v = generateVerifier();
      expect(await pkceValid(v, v, "plain")).toBe(false);
    });

    test("verifier produces RFC-compliant base64url (no +, /, =)", () => {
      for (let i = 0; i < 20; i++) {
        const v = generateVerifier();
        expect(v).not.toMatch(/[+/=]/);
      }
    });

    test("two verifiers are distinct", () => {
      expect(generateVerifier()).not.toBe(generateVerifier());
    });
  });

  describe("authorize endpoint", () => {
    test("valid request → 302 to /auth/login with login_challenge", async () => {
      const challenge = await computeChallenge(generateVerifier());
      const resp = await doAuthorize({ challenge });

      expect(resp.status).toBe(302);
      const loc = locationOf(resp);
      expect(loc.pathname).toBe("/auth/login");
      expect(loc.searchParams.get("login_challenge")).toBeTruthy();
    });

    test("unknown client_id → 401 (no redirect — redirect_uri untrusted)", async () => {
      const url = new URL(`${BASE}/oauth/authorize`);
      url.searchParams.set("client_id", "nobody");
      url.searchParams.set("redirect_uri", "https://app.example.com/callback");
      url.searchParams.set("response_type", "code");
      url.searchParams.set("scope", "openid");
      url.searchParams.set("state", "s");
      url.searchParams.set(
        "code_challenge",
        await computeChallenge(generateVerifier()),
      );
      url.searchParams.set("code_challenge_method", "S256");
      const resp = await fetch(url.toString(), { redirect: "manual" });
      expect(resp.status).toBe(401);
    });

    test("unregistered redirect_uri → 400 (no redirect)", async () => {
      const url = new URL(`${BASE}/oauth/authorize`);
      url.searchParams.set("client_id", "auto-client");
      url.searchParams.set("redirect_uri", "https://evil.example.com/callback");
      url.searchParams.set("response_type", "code");
      url.searchParams.set("scope", "openid");
      url.searchParams.set("state", "s");
      url.searchParams.set(
        "code_challenge",
        await computeChallenge(generateVerifier()),
      );
      url.searchParams.set("code_challenge_method", "S256");
      const resp = await fetch(url.toString(), { redirect: "manual" });
      expect(resp.status).toBe(400);
    });

    test("missing code_challenge → error redirect", async () => {
      const url = new URL(`${BASE}/oauth/authorize`);
      url.searchParams.set("client_id", "auto-client");
      url.searchParams.set("redirect_uri", "https://app.example.com/callback");
      url.searchParams.set("response_type", "code");
      url.searchParams.set("scope", "openid");
      url.searchParams.set("state", "s");
      const resp = await fetch(url.toString(), { redirect: "manual" });
      expect(resp.status).toBe(302);
      expect(locationOf(resp).searchParams.get("error")).toBe(
        "invalid_request",
      );
    });

    test("plain code_challenge_method → error redirect", async () => {
      const verifier = generateVerifier();
      const resp = await doAuthorize({ challenge: verifier, method: "plain" });
      expect(resp.status).toBe(302);
      expect(locationOf(resp).searchParams.get("error")).toBe(
        "invalid_request",
      );
    });

    test("unsupported response_type → error redirect", async () => {
      const url = new URL(`${BASE}/oauth/authorize`);
      url.searchParams.set("client_id", "auto-client");
      url.searchParams.set("redirect_uri", "https://app.example.com/callback");
      url.searchParams.set("response_type", "token"); // implicit — not supported
      url.searchParams.set("scope", "openid");
      url.searchParams.set("state", "s");
      url.searchParams.set(
        "code_challenge",
        await computeChallenge(generateVerifier()),
      );
      url.searchParams.set("code_challenge_method", "S256");
      const resp = await fetch(url.toString(), { redirect: "manual" });
      expect(locationOf(resp).searchParams.get("error")).toBe(
        "unsupported_response_type",
      );
    });

    test("scope not allowed for client → error redirect", async () => {
      const challenge = await computeChallenge(generateVerifier());
      const resp = await doAuthorize({ challenge, scope: "openid admin" }); // admin not in client.scopes
      expect(locationOf(resp).searchParams.get("error")).toBe("invalid_scope");
    });

    test("state is preserved in error redirect", async () => {
      const verifier = generateVerifier();
      const resp = await doAuthorize({
        challenge: verifier,
        method: "plain",
        state: "my-state",
      });
      expect(locationOf(resp).searchParams.get("state")).toBe("my-state");
    });
  });

  describe("auto-grant happy path", () => {
    test("full flow returns access token, refresh token, token_type, scope", async () => {
      const { tokens } = await fullAutoGrantFlow();
      expect(tokens.access_token).toBeTruthy();
      expect(tokens.token_type).toBe("Bearer");
      expect(tokens.expires_in).toBe(900);
      expect(tokens.refresh_token).toBeTruthy();
      expect(tokens.scope).toBe("openid profile");
    });

    test("access token is a valid ES256 JWT with correct claims", async () => {
      const { tokens } = await fullAutoGrantFlow();
      const { payload } = await jwtVerify(tokens.access_token, publicKey);
      expect(payload.sub).toBe("user-alice");
      expect(payload.iss).toBe("https://auth.test");
      expect((payload as any).client_id).toBe("auto-client");
      expect(Array.isArray((payload as any).scope)).toBe(true);
      expect(((payload as any).scope as string[]).sort()).toEqual(
        ["openid", "profile"].sort(),
      );
      // not expired
      expect(payload.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
    });

    test("state is echoed back to redirect_uri", async () => {
      const verifier = generateVerifier();
      const challenge = await computeChallenge(verifier);
      const authResp = await doAuthorize({ challenge, state: "unique-xyz" });
      const loginChallenge =
        locationOf(authResp).searchParams.get("login_challenge")!;
      const loginResp = await doLogin(loginChallenge);
      expect(locationOf(loginResp).searchParams.get("state")).toBe(
        "unique-xyz",
      );
    });

    test("invalid credentials → 401", async () => {
      const challenge = await computeChallenge(generateVerifier());
      const authResp = await doAuthorize({ challenge });
      const loginChallenge =
        locationOf(authResp).searchParams.get("login_challenge")!;
      const resp = await doLogin(
        loginChallenge,
        "alice@example.com",
        "wrong-password",
      );
      expect(resp.status).toBe(401);
    });
  });

  describe("token exchange", () => {
    test("wrong code_verifier → invalid_grant", async () => {
      const verifier = generateVerifier();
      const challenge = await computeChallenge(verifier);
      const authResp = await doAuthorize({ challenge });
      const loginChallenge =
        locationOf(authResp).searchParams.get("login_challenge")!;
      const loginResp = await doLogin(loginChallenge);
      const code = locationOf(loginResp).searchParams.get("code")!;

      const resp = await doTokenExchange(code, generateVerifier()); // different verifier
      expect(resp.status).toBe(400);
      expect((await resp.json()).error).toBe("invalid_grant");
    });

    test("code is single-use: replay → invalid_grant", async () => {
      const verifier = generateVerifier();
      const challenge = await computeChallenge(verifier);
      const authResp = await doAuthorize({ challenge });
      const loginChallenge =
        locationOf(authResp).searchParams.get("login_challenge")!;
      const loginResp = await doLogin(loginChallenge);
      const code = locationOf(loginResp).searchParams.get("code")!;

      await doTokenExchange(code, verifier); // first use
      const replay = await doTokenExchange(code, verifier); // replay
      expect(replay.status).toBe(400);
      expect((await replay.json()).error).toBe("invalid_grant");
    });

    test("redirect_uri mismatch → invalid_grant", async () => {
      const verifier = generateVerifier();
      const challenge = await computeChallenge(verifier);
      const authResp = await doAuthorize({ challenge });
      const loginChallenge =
        locationOf(authResp).searchParams.get("login_challenge")!;
      const loginResp = await doLogin(loginChallenge);
      const code = locationOf(loginResp).searchParams.get("code")!;

      const resp = await doTokenExchange(
        code,
        verifier,
        "https://evil.example.com/callback",
      );
      expect(resp.status).toBe(400);
      expect((await resp.json()).error).toBe("invalid_grant");
    });

    test("expired auth code → invalid_grant", async () => {
      const verifier = generateVerifier();
      const challenge = await computeChallenge(verifier);
      const authResp = await doAuthorize({ challenge });
      const loginChallenge =
        locationOf(authResp).searchParams.get("login_challenge")!;
      const loginResp = await doLogin(loginChallenge);
      const code = locationOf(loginResp).searchParams.get("code")!;

      // Backdate the expiry
      authCodes.get(code)!.expiresAt = new Date(Date.now() - 1000);

      const resp = await doTokenExchange(code, verifier);
      expect(resp.status).toBe(400);
      expect((await resp.json()).error).toBe("invalid_grant");
    });

    test("unsupported grant_type → unsupported_grant_type", async () => {
      const resp = await fetch(`${BASE}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "implicit" }),
      });
      expect(resp.status).toBe(400);
      expect((await resp.json()).error).toBe("unsupported_grant_type");
    });
  });

  describe("refresh token rotation", () => {
    test("refresh returns new access + refresh token", async () => {
      const { tokens } = await fullAutoGrantFlow();
      const resp = await doRefresh(tokens.refresh_token);
      expect(resp.status).toBe(200);
      const newTokens = await resp.json();
      expect(newTokens.access_token).toBeTruthy();
      expect(newTokens.refresh_token).toBeTruthy();
      expect(newTokens.refresh_token).not.toBe(tokens.refresh_token); // rotated
    });

    test("new access token has correct claims", async () => {
      const { tokens } = await fullAutoGrantFlow();
      const newTokens = await (await doRefresh(tokens.refresh_token)).json();
      const { payload } = await jwtVerify(newTokens.access_token, publicKey);
      expect(payload.sub).toBe("user-alice");
    });

    test("refresh token is single-use: original replay → invalid_grant", async () => {
      const { tokens } = await fullAutoGrantFlow();
      await doRefresh(tokens.refresh_token); // consume it
      const resp = await doRefresh(tokens.refresh_token); // replay original
      expect(resp.status).toBe(400);
      expect((await resp.json()).error).toBe("invalid_grant");
    });

    test("refresh replay revokes the entire grant (new token also invalid)", async () => {
      const { tokens } = await fullAutoGrantFlow();
      const { refresh_token: newRefreshToken } = await (
        await doRefresh(tokens.refresh_token)
      ).json();

      // Replay the old token — triggers grant revocation
      await doRefresh(tokens.refresh_token);

      // The legitimately issued new token should also be gone
      const resp = await doRefresh(newRefreshToken);
      expect(resp.status).toBe(400);
      expect((await resp.json()).error).toBe("invalid_grant");
    });

    test("unknown refresh token → invalid_grant", async () => {
      const resp = await doRefresh("nonexistent-token");
      expect(resp.status).toBe(400);
      expect((await resp.json()).error).toBe("invalid_grant");
    });
  });

  describe("consent flow (non-auto-grant client)", () => {
    async function consentFlow(action: "allow" | "deny") {
      const verifier = generateVerifier();
      const challenge = await computeChallenge(verifier);

      const authResp = await doAuthorize({
        clientId: "consent-client",
        challenge,
      });
      const loginChallenge =
        locationOf(authResp).searchParams.get("login_challenge")!;

      // Login redirects to /oauth/consent, not directly to redirect_uri
      const loginResp = await doLogin(loginChallenge);
      const loginLoc = locationOf(loginResp);
      expect(loginLoc.pathname).toBe("/oauth/consent");

      // Extract login_session cookie
      const setCookie = loginResp.headers.get("set-cookie")!;
      const sessionToken = setCookie.match(/login_session=([^;]+)/)![1];
      const consentLoc = loginLoc;

      // POST consent
      return {
        consentResp: await fetch(
          `${BASE}${consentLoc.pathname}${consentLoc.search}`,
          {
            method: "POST",
            redirect: "manual",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
              Cookie: `login_session=${sessionToken}`,
            },
            body: new URLSearchParams({
              login_challenge: loginChallenge,
              action,
            }),
          },
        ),
        verifier,
      };
    }

    test("allow → auth code issued at redirect_uri", async () => {
      const { consentResp, verifier } = await consentFlow("allow");
      expect(consentResp.status).toBe(302);
      const code = locationOf(consentResp).searchParams.get("code")!;
      expect(code).toBeTruthy();

      const tokenResp = await fetch(`${BASE}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: "https://app.example.com/callback",
          client_id: "consent-client",
          code_verifier: verifier,
        }),
      });
      expect(tokenResp.status).toBe(200);
      const t = await tokenResp.json();
      expect(t.access_token).toBeTruthy();
    });

    test("deny → access_denied error at redirect_uri", async () => {
      const { consentResp } = await consentFlow("deny");
      expect(consentResp.status).toBe(302);
      expect(locationOf(consentResp).searchParams.get("error")).toBe(
        "access_denied",
      );
    });

    test("consent GET without session cookie → 401", async () => {
      const challenge = await computeChallenge(generateVerifier());
      const authResp = await doAuthorize({
        clientId: "consent-client",
        challenge,
      });
      const loginChallenge =
        locationOf(authResp).searchParams.get("login_challenge")!;
      await doLogin(loginChallenge); // creates the challenge entry

      const resp = await fetch(
        `${BASE}/oauth/consent?login_challenge=${loginChallenge}`,
        {
          redirect: "manual",
        },
      );
      expect(resp.status).toBe(401);
    });
  });
});
