/**
 * Integration tests for the account/security page and the sso_session ->
 * keys API bridge. Requires the oauth server to be running: go run ./cmd/oauth
 *
 * Usage:
 *   cd apps/oauth/tests
 *   bun test account.test.ts
 *
 * Override server URL:
 *   SERVER_URL=http://localhost:9090 bun test
 */

import { describe, test, expect, beforeAll } from "bun:test";

const BASE = process.env.SERVER_URL ?? "http://localhost:8080";
const CLIENT_ID = "neoworks.dev";
const REDIRECT_URI = "http://neoworks.localhost/auth/callback";

// ── Helpers ───────────────────────────────────────────────────────────────────

function randomBase64url(bytes = 32): string {
  return btoa(
    String.fromCharCode(...crypto.getRandomValues(new Uint8Array(bytes))),
  )
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

/**
 * The AMK wrapper fields are normally generated client-side (see
 * signup.html, which uses libsodium for Argon2id + secretbox + crypto_box).
 * The server stores these blobs opaquely, so random data is sufficient here.
 */
function amkFormFields(
  overrides: Record<string, string> = {},
): Record<string, string> {
  return {
    password_wrapped_amk: randomBase64url(48),
    recovery_wrapped_amk: randomBase64url(48),
    argon2_salt: randomBase64url(16),
    argon2_time: "2",
    argon2_memory: "67108864",
    argon2_threads: "1",
    argon2_keylen: "32",
    device_public_key: randomBase64url(32),
    device_wrapped_amk: randomBase64url(48),
    ...overrides,
  };
}

async function getLoginChallenge(): Promise<{
  loginChallenge: string;
  verifier: string;
}> {
  const verifier = randomBase64url(32);
  const challenge = await pkceChallenge(verifier);

  const url = new URL(`${BASE}/oauth/authorize`);
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("redirect_uri", REDIRECT_URI);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid profile email");
  url.searchParams.set("state", "test");
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");

  const resp = await fetch(url.toString(), { redirect: "manual" });
  if (resp.status !== 302)
    throw new Error(`authorize: expected 302, got ${resp.status}`);

  const loginChallenge = new URL(resp.headers.get("location")!).searchParams.get(
    "login_challenge",
  );
  if (!loginChallenge) throw new Error("no login_challenge in redirect");

  return { loginChallenge, verifier };
}

function extractCookie(resp: Response, name: string): string | null {
  const cookies = resp.headers.getSetCookie();
  const match = cookies.find((cookie) => cookie.startsWith(`${name}=`));
  if (!match) return null;

  return match.split(";")[0].split("=")[1];
}

/**
 * Signs up a brand-new user and returns the resulting sso_session cookie
 * value plus the email and device key material used to create the account.
 */
async function signUpNewUser(): Promise<{
  email: string;
  ssoSession: string;
  devicePublicKey: string;
}> {
  const { loginChallenge } = await getLoginChallenge();
  const email = `account-${Date.now()}-${Math.random().toString(36).slice(2)}@test.example.com`;
  const fields = amkFormFields();

  // Signup now requires a verified email. Run the code dance first (the server
  // echoes the code back in DEBUG mode).
  const sendResp = await fetch(`${BASE}/auth/signup/send-code`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  const { code } = await sendResp.json();
  if (!code)
    throw new Error("send-code did not return a code — run server with DEBUG=true");
  await fetch(`${BASE}/auth/signup/verify-code`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, code }),
  });

  const resp = await fetch(`${BASE}/auth/signup`, {
    method: "POST",
    redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      first_name: "Test",
      last_name: "User",
      email,
      password: "test-password-123",
      login_challenge: loginChallenge,
      ...fields,
    }),
  });
  if (resp.status !== 302)
    throw new Error(`signup: expected 302, got ${resp.status}`);

  const ssoSession = extractCookie(resp, "sso_session");
  if (!ssoSession) throw new Error("signup did not set sso_session cookie");

  return { email, ssoSession, devicePublicKey: fields.device_public_key };
}

// ── Setup ─────────────────────────────────────────────────────────────────────

beforeAll(async () => {
  try {
    await fetch(`${BASE}/.well-known/openid-configuration`, {
      signal: AbortSignal.timeout(2000),
    });
  } catch {
    console.error(
      `\nServer not reachable at ${BASE} — start it with: go run ./cmd/oauth\n`,
    );
    process.exit(1);
  }
});

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("sso_session bridge to the keys API", () => {
  test("GET /api/v1/keys/devices without cookie → 401", async () => {
    const resp = await fetch(`${BASE}/api/v1/keys/devices`);
    expect(resp.status).toBe(401);
  });

  test("GET /api/v1/keys/devices with sso_session cookie → 200 with signup device", async () => {
    const { ssoSession, devicePublicKey } = await signUpNewUser();

    const resp = await fetch(`${BASE}/api/v1/keys/devices`, {
      headers: { Cookie: `sso_session=${ssoSession}` },
    });
    expect(resp.status).toBe(200);

    const devices = await resp.json();
    expect(Array.isArray(devices)).toBe(true);
    expect(devices.some((device: any) => device.public_key === devicePublicKey)).toBe(true);
  });
});

describe("GET /account/security", () => {
  test("without cookie → redirect", async () => {
    const resp = await fetch(`${BASE}/account/security`, { redirect: "manual" });
    expect(resp.status).toBe(302);
  });

  test("with sso_session cookie → 200 with account email", async () => {
    const { email, ssoSession } = await signUpNewUser();

    const resp = await fetch(`${BASE}/account/security`, {
      headers: { Cookie: `sso_session=${ssoSession}` },
    });
    expect(resp.status).toBe(200);

    const body = await resp.text();
    expect(body).toContain(email);
  });
});
