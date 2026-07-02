/**
 * Integration tests for the forgot-password / reset flow. Requires the oauth
 * server running with DEBUG=true (so codes are echoed instead of only emailed):
 *   go run ./cmd/oauth
 *
 * Usage:
 *   cd apps/oauth/tests
 *   bun test reset.test.ts
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

async function getLoginChallenge(): Promise<string> {
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
  const loginChallenge = new URL(
    resp.headers.get("location")!,
  ).searchParams.get("login_challenge");
  if (!loginChallenge) throw new Error("no login_challenge in redirect");
  return loginChallenge;
}

async function postJSON(path: string, body: unknown): Promise<Response> {
  return fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

/**
 * Creates a verified account and returns its email plus the recovery-wrapped AMK
 * blob it was registered with. The blob is opaque to the server (random here),
 * which is enough to assert the reset endpoints round-trip it correctly.
 */
async function createAccount(): Promise<{
  email: string;
  recoveryWrappedAMK: string;
}> {
  const loginChallenge = await getLoginChallenge();
  const email = `reset-${Date.now()}-${Math.floor(Math.random() * 1e6)}@test.example.com`;
  const recoveryWrappedAMK = randomBase64url(48);

  const sendResp = await postJSON("/auth/signup/send-code", { email });
  const { code } = await sendResp.json();
  if (!code)
    throw new Error("DEBUG=true required so signup send-code returns a code");
  await postJSON("/auth/signup/verify-code", { email, code });

  const signupResp = await fetch(`${BASE}/auth/signup`, {
    method: "POST",
    redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      first_name: "Reset",
      last_name: "User",
      email,
      password: "original-password-1",
      login_challenge: loginChallenge,
      password_wrapped_amk: randomBase64url(48),
      recovery_wrapped_amk: recoveryWrappedAMK,
      argon2_salt: randomBase64url(16),
      argon2_time: "2",
      argon2_memory: "67108864",
      argon2_threads: "1",
      argon2_keylen: "32",
      device_public_key: randomBase64url(32),
      device_wrapped_amk: randomBase64url(48),
    }),
  });
  if (signupResp.status !== 302)
    throw new Error(`signup: expected 302, got ${signupResp.status}`);

  return { email, recoveryWrappedAMK };
}

/** Requests a reset code and returns it from the debug-only redirect param. */
async function requestResetCode(email: string): Promise<string | null> {
  const resp = await fetch(`${BASE}/auth/forgot`, {
    method: "POST",
    redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ email }),
  });
  expect(resp.status).toBe(303);
  const location = new URL(resp.headers.get("location")!, BASE);
  expect(location.pathname).toBe("/auth/reset");
  return location.searchParams.get("code");
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

describe("password reset flow", () => {
  test("forgot for an unknown email still redirects, with no code", async () => {
    const code = await requestResetCode(
      `nobody-${Date.now()}@test.example.com`,
    );
    expect(code).toBeNull();
  });

  test("verify-code releases the recovery blob and a reset token", async () => {
    const { email, recoveryWrappedAMK } = await createAccount();
    const code = await requestResetCode(email);
    expect(code).toBeTruthy();

    const resp = await postJSON("/auth/reset/verify-code", { email, code });
    expect(resp.status).toBe(200);
    const data = await resp.json();
    expect(data.reset_token).toBeTruthy();
    expect(data.recovery_wrapped_amk).toBe(recoveryWrappedAMK);
  });

  test("wrong code is rejected", async () => {
    const { email } = await createAccount();
    await requestResetCode(email);

    const resp = await postJSON("/auth/reset/verify-code", {
      email,
      code: "000000",
    });
    expect(resp.status).toBe(400);
  });

  test("reset updates credentials and the token is single-use", async () => {
    const { email } = await createAccount();
    const code = await requestResetCode(email);
    const verifyResp = await postJSON("/auth/reset/verify-code", {
      email,
      code,
    });
    const { reset_token } = await verifyResp.json();

    const newCredentials = {
      reset_token,
      password: "brand-new-password-2",
      password_wrapped_amk: randomBase64url(48),
      argon2_salt: randomBase64url(16),
      argon2_time: 2,
      argon2_memory: 67108864,
      argon2_threads: 1,
      argon2_keylen: 32,
    };

    const resetResp = await postJSON("/auth/reset", newCredentials);
    expect(resetResp.status).toBe(200);

    // Token is consumed — replaying it must fail.
    const replay = await postJSON("/auth/reset", newCredentials);
    expect(replay.status).toBe(400);
  });

  test("reset with a bogus token is rejected", async () => {
    const resp = await postJSON("/auth/reset", {
      reset_token: "not-a-real-token",
      password: "brand-new-password-2",
      password_wrapped_amk: randomBase64url(48),
      argon2_salt: randomBase64url(16),
      argon2_time: 2,
      argon2_memory: 67108864,
      argon2_threads: 1,
      argon2_keylen: 32,
    });
    expect(resp.status).toBe(400);
  });
});
