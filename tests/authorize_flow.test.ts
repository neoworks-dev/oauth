/**
 * Live integration tests for the authorization endpoint and its callbacks.
 *
 * Drives GET /oauth/authorize → /oauth/callback/login → /oauth/callback/consent
 * → POST /oauth/token as a full end-to-end flow, plus the security-critical
 * rejections around it: open-redirect defense, PKCE enforcement at authorize
 * time, scope validation, challenge single-use/expiry, state (CSRF) round-trip,
 * and consent-scope clamping.
 */
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import {
  PUBLIC_CLIENT_ID,
  CONFIDENTIAL_CLIENT_ID,
  REDIRECT_URI,
  VALID_CODE_VERIFIER,
  getAuthorize,
  authorizeParams,
  postLoginCallback,
  postConsentCallback,
  redirectParam,
  postToken,
  verifyAccessToken,
  freshUserId,
  setupFixtures,
  teardownFixtures,
} from "./helpers/token_test_helpers";

beforeAll(setupFixtures);
afterAll(teardownFixtures);

// Advances a login challenge through the consent screen and returns the auth
// code delivered to the redirect URI. A fresh user id keeps the consent path
// live — a reused user would hit the "already granted" shortcut and skip it.
async function completeConsent(
  loginChallenge: string,
  scopes: string[],
  userId: string,
): Promise<{ redirectBody: any; code: string | null }> {
  const login = await postLoginCallback(loginChallenge, userId);
  const consentChallenge = new URL(login.body.redirect, "http://x").searchParams.get("consent_challenge");
  expect(consentChallenge).toBeString();
  const consent = await postConsentCallback(consentChallenge!, true, scopes);
  return { redirectBody: consent.body, code: redirectParam(consent.body, "code") };
}

describe("authorize endpoint — request validation", () => {
  test("a valid request issues a login challenge", async () => {
    const result = await getAuthorize(authorizeParams());
    expect(result.status).toBe(302);
    expect(result.loginChallenge).toBeString();
    expect(new URL(result.location!, "http://x").pathname).toBe("/auth/login");
  });

  test("a missing client_id is rejected without issuing a challenge", async () => {
    const result = await getAuthorize(authorizeParams({ client_id: "" }));
    expect(result.loginChallenge).toBeNull();
    // Bounces to the on-domain error page, never to the redirect_uri.
    expect(result.location ?? "").not.toContain("zztest.example");
  });

  test("an unknown client is rejected", async () => {
    const result = await getAuthorize(authorizeParams({ client_id: "zztest-nonexistent" }));
    expect(result.loginChallenge).toBeNull();
    expect(result.location ?? "").not.toContain("zztest.example");
  });

  test("an unregistered redirect_uri is refused and never redirected to (open-redirect defense)", async () => {
    const result = await getAuthorize(authorizeParams({ redirect_uri: "https://attacker.example/steal" }));
    expect(result.loginChallenge).toBeNull();
    expect(result.location ?? "").not.toContain("attacker.example");
  });

  test("a missing redirect_uri is rejected", async () => {
    const result = await getAuthorize(authorizeParams({ redirect_uri: "" }));
    expect(result.loginChallenge).toBeNull();
  });
});

describe("authorize endpoint — errors bounce back to the registered redirect_uri", () => {
  test("a non-code response_type is an unsupported_response_type redirect", async () => {
    const result = await getAuthorize(authorizeParams({ response_type: "token" }));
    const redirect = new URL(result.location!, "http://x");
    expect(redirect.origin + redirect.pathname).toBe(REDIRECT_URI);
    expect(redirect.searchParams.get("error")).toBe("unsupported_response_type");
    expect(redirect.searchParams.get("state")).toBe("zztest-state-xyz");
  });

  test("a public client without a code_challenge is rejected (PKCE required)", async () => {
    const result = await getAuthorize(authorizeParams({ code_challenge: "" }));
    const redirect = new URL(result.location!, "http://x");
    expect(redirect.searchParams.get("error")).toBe("invalid_request");
  });

  test("a non-S256 code_challenge_method is rejected", async () => {
    const result = await getAuthorize(authorizeParams({ code_challenge_method: "plain" }));
    const redirect = new URL(result.location!, "http://x");
    expect(redirect.searchParams.get("error")).toBe("invalid_request");
  });

  test("a scope outside the client registration is rejected at authorize time", async () => {
    const result = await getAuthorize(authorizeParams({ scope: "admin:everything" }));
    const redirect = new URL(result.location!, "http://x");
    expect(redirect.searchParams.get("error")).toBe("invalid_scope");
  });
});

describe("login/consent callbacks", () => {
  test("an unknown login challenge is rejected", async () => {
    const result = await postLoginCallback("zztest-never-issued");
    expect(result.status).toBe(400);
    expect(result.body.error).toBe("invalid_challenge");
  });

  test("a login challenge is single-use", async () => {
    const authorize = await getAuthorize(authorizeParams());
    const first = await postLoginCallback(authorize.loginChallenge!);
    expect(first.status).toBe(200);
    const second = await postLoginCallback(authorize.loginChallenge!);
    expect(second.status).toBe(400);
    expect(second.body.error).toBe("invalid_challenge");
  });

  test("an unknown consent challenge is rejected", async () => {
    const result = await postConsentCallback("zztest-never-issued", true, ["storage:read"]);
    expect(result.status).toBe(400);
    expect(result.body.error).toBe("invalid_challenge");
  });

  test("denying consent returns access_denied and preserves state, issues no code", async () => {
    const authorize = await getAuthorize(authorizeParams());
    const login = await postLoginCallback(authorize.loginChallenge!, freshUserId());
    const consentChallenge = new URL(login.body.redirect, "http://x").searchParams.get("consent_challenge");
    const consent = await postConsentCallback(consentChallenge!, false, []);
    expect(redirectParam(consent.body, "error")).toBe("access_denied");
    expect(redirectParam(consent.body, "state")).toBe("zztest-state-xyz");
    expect(redirectParam(consent.body, "code")).toBeNull();
  });
});

describe("authorize flow — end to end", () => {
  test("full flow yields an auth code that exchanges for a working token", async () => {
    const userId = freshUserId();
    const authorize = await getAuthorize(authorizeParams());
    const { redirectBody, code } = await completeConsent(authorize.loginChallenge!, ["storage:read"], userId);
    expect(code).toBeString();
    // state must survive the whole flow to the final redirect (CSRF defense).
    expect(redirectParam(redirectBody, "state")).toBe("zztest-state-xyz");

    const token = await postToken({
      grant_type: "authorization_code",
      code: code!,
      redirect_uri: REDIRECT_URI,
      code_verifier: VALID_CODE_VERIFIER,
    });
    expect(token.status).toBe(200);
    const { payload } = await verifyAccessToken(token.body.access_token);
    expect(payload.sub).toBe(userId);
    expect((payload as any).client_id).toBe(PUBLIC_CLIENT_ID);
    expect((payload as any).scope).toEqual(["storage:read"]);
  });

  test("consent cannot widen scope beyond what authorize requested", async () => {
    // authorize asks for storage:read only; the browser tries to grant more.
    const authorize = await getAuthorize(authorizeParams({ scope: "storage:read" }));
    const { code } = await completeConsent(
      authorize.loginChallenge!,
      ["storage:read", "storage:write", "admin:everything"],
      freshUserId(),
    );
    expect(code).toBeString();
    const token = await postToken({
      grant_type: "authorization_code",
      code: code!,
      redirect_uri: REDIRECT_URI,
      code_verifier: VALID_CODE_VERIFIER,
    });
    expect(token.status).toBe(200);
    // Only the originally requested (and client-registered) scope is granted.
    expect(token.body.scope).toBe("storage:read");
  });

  test("consent can narrow scope below what authorize requested", async () => {
    const authorize = await getAuthorize(authorizeParams({ scope: "storage:read storage:write" }));
    const { code } = await completeConsent(authorize.loginChallenge!, ["storage:read"], freshUserId());
    const token = await postToken({
      grant_type: "authorization_code",
      code: code!,
      redirect_uri: REDIRECT_URI,
      code_verifier: VALID_CODE_VERIFIER,
    });
    expect(token.status).toBe(200);
    expect(token.body.scope).toBe("storage:read");
  });

  test("the code from the browser flow is bound to the client table and is exchangeable", async () => {
    // Regression guard: the callback once minted codes bound to `oauth_client`,
    // which the token endpoint could not resolve (500 on refresh-token save).
    const authorize = await getAuthorize(authorizeParams());
    const { code } = await completeConsent(authorize.loginChallenge!, ["storage:read"], freshUserId());
    const token = await postToken({
      grant_type: "authorization_code",
      code: code!,
      redirect_uri: REDIRECT_URI,
      code_verifier: VALID_CODE_VERIFIER,
    });
    expect(token.status).toBe(200);
    expect(token.body.refresh_token).toBeString();
  });

  test("a code cannot be exchanged with a redirect_uri other than the one bound to it", async () => {
    const authorize = await getAuthorize(authorizeParams());
    const { code } = await completeConsent(authorize.loginChallenge!, ["storage:read"], freshUserId());
    const token = await postToken({
      grant_type: "authorization_code",
      code: code!,
      redirect_uri: "https://attacker.example/callback",
      code_verifier: VALID_CODE_VERIFIER,
    });
    expect(token.status).toBe(400);
    expect(token.body.error).toBe("invalid_grant");
  });
});
