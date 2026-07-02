/**
 * Integration tests for the signup endpoint's Account Master Key (AMK)
 * requirements. Requires the oauth server to be running: go run ./cmd/oauth
 *
 * Usage:
 *   cd apps/oauth/tests
 *   bun test signup.test.ts
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

/**
 * Drives the email verification step that now gates signup. Requires the server
 * to run with DEBUG=true, which echoes the code back instead of only emailing it.
 */
async function verifyEmail(email: string): Promise<void> {
  const sendResp = await fetch(`${BASE}/auth/signup/send-code`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  if (!sendResp.ok) throw new Error(`send-code: ${sendResp.status}`);
  const { code } = await sendResp.json();
  if (!code)
    throw new Error(
      "send-code did not return a code — run the server with DEBUG=true",
    );

  const verifyResp = await fetch(`${BASE}/auth/signup/verify-code`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, code }),
  });
  if (!verifyResp.ok) throw new Error(`verify-code: ${verifyResp.status}`);
}

async function postSignup(
  loginChallenge: string,
  email: string,
  fields: Record<string, string>,
): Promise<Response> {
  return fetch(`${BASE}/auth/signup`, {
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

describe("signup with Account Master Key material", () => {
  test("signup with AMK fields → auth code → token exchange succeeds", async () => {
    const { loginChallenge, verifier } = await getLoginChallenge();
    const email = `amk-${Date.now()}@test.example.com`;

    await verifyEmail(email);
    const signupResp = await postSignup(loginChallenge, email, amkFormFields());
    expect(signupResp.status).toBe(302);

    const code = new URL(signupResp.headers.get("location")!).searchParams.get(
      "code",
    );
    expect(code).toBeTruthy();

    const tokenResp = await fetch(`${BASE}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code!,
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        code_verifier: verifier,
      }),
    });
    expect(tokenResp.status).toBe(200);
    const tokens = await tokenResp.json();
    expect(tokens.access_token).toBeTruthy();
  });

  test("missing AMK fields → 400", async () => {
    const { loginChallenge } = await getLoginChallenge();
    const email = `no-amk-${Date.now()}@test.example.com`;

    await verifyEmail(email);
    const resp = await postSignup(loginChallenge, email, {});
    expect(resp.status).toBe(400);
  });

  test("signup without a verified email is blocked", async () => {
    const { loginChallenge } = await getLoginChallenge();
    const email = `unverified-${Date.now()}@test.example.com`;

    // Skip verifyEmail — the gate should refuse to create the account.
    const resp = await postSignup(loginChallenge, email, amkFormFields());
    expect(resp.status).not.toBe(302);
  });

  test("non-positive argon2 param → 400", async () => {
    const { loginChallenge } = await getLoginChallenge();
    const email = `bad-argon2-${Date.now()}@test.example.com`;

    await verifyEmail(email);
    const resp = await postSignup(
      loginChallenge,
      email,
      amkFormFields({ argon2_time: "0" }),
    );
    expect(resp.status).toBe(400);
  });
});
