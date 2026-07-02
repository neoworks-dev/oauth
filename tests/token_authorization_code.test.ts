/** Live integration tests: authorization_code grant on POST /oauth/token. */
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import {
  CONFIDENTIAL_CLIENT_ID,
  CONFIDENTIAL_CLIENT_SECRET,
  PUBLIC_CLIENT_ID,
  TEST_USER_ID,
  REDIRECT_URI,
  postToken,
  plantAuthCode,
  s256Challenge,
  exchangeFreshAuthCode,
  verifyAccessToken,
  setupFixtures,
  teardownFixtures,
} from "./helpers/token_test_helpers";

beforeAll(setupFixtures);
afterAll(teardownFixtures);

describe("authorization_code grant (public client, PKCE)", () => {
  test("exchanges a valid code + S256 verifier for tokens", async () => {
    const result = await exchangeFreshAuthCode();
    expect(result.status).toBe(200);
    expect(result.body.access_token).toBeString();
    expect(result.body.refresh_token).toBeString();
    expect(result.body.scope).toBe("storage:read");
  });

  test("access token carries the user as subject", async () => {
    const result = await exchangeFreshAuthCode();
    const { payload } = await verifyAccessToken(result.body.access_token);
    expect(payload.sub).toBe(TEST_USER_ID);
    expect((payload as any).client_id).toBe(PUBLIC_CLIENT_ID);
  });

  test("a code is single-use", async () => {
    const verifier = "zztest-verifier-" + crypto.randomUUID();
    const code = await plantAuthCode({ codeChallenge: await s256Challenge(verifier), codeChallengeMethod: "S256" });
    const params = { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: verifier };
    const first = await postToken(params);
    expect(first.status).toBe(200);
    const second = await postToken(params);
    expect(second.status).toBe(400);
    expect(second.body.error).toBe("invalid_grant");
  });

  test("a wrong verifier is rejected and burns the code", async () => {
    const verifier = "zztest-verifier-" + crypto.randomUUID();
    const code = await plantAuthCode({ codeChallenge: await s256Challenge(verifier), codeChallengeMethod: "S256" });
    const wrong = await postToken({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: "not-the-verifier",
    });
    expect(wrong.status).toBe(400);
    expect(wrong.body.error).toBe("invalid_grant");
    // Consume-then-verify: the failed attempt must not leave the code usable.
    const retry = await postToken({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
    });
    expect(retry.status).toBe(400);
  });

  test("a missing verifier is rejected for a public client", async () => {
    const code = await plantAuthCode({ codeChallenge: await s256Challenge("x"), codeChallengeMethod: "S256" });
    const result = await postToken({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI });
    expect(result.status).toBe(400);
    expect(result.body.error).toBe("invalid_grant");
  });

  test("the plain challenge method is rejected even with a matching verifier", async () => {
    const verifier = "zztest-plain-verifier";
    const code = await plantAuthCode({ codeChallenge: verifier, codeChallengeMethod: "plain" });
    const result = await postToken({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
    });
    expect(result.status).toBe(400);
    expect(result.body.error).toBe("invalid_grant");
  });

  test("an expired code is rejected", async () => {
    const verifier = "zztest-verifier-" + crypto.randomUUID();
    const code = await plantAuthCode({
      codeChallenge: await s256Challenge(verifier),
      codeChallengeMethod: "S256",
      expiresInSeconds: -5,
    });
    const result = await postToken({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
    });
    expect(result.status).toBe(400);
    expect(result.body.error).toBe("invalid_grant");
  });

  test("a redirect_uri mismatch is rejected", async () => {
    const verifier = "zztest-verifier-" + crypto.randomUUID();
    const code = await plantAuthCode({ codeChallenge: await s256Challenge(verifier), codeChallengeMethod: "S256" });
    const result = await postToken({
      grant_type: "authorization_code",
      code,
      redirect_uri: "https://attacker.example/callback",
      code_verifier: verifier,
    });
    expect(result.status).toBe(400);
    expect(result.body.error).toBe("invalid_grant");
  });

  test("a missing redirect_uri is rejected", async () => {
    const verifier = "zztest-verifier-" + crypto.randomUUID();
    const code = await plantAuthCode({ codeChallenge: await s256Challenge(verifier), codeChallengeMethod: "S256" });
    const result = await postToken({ grant_type: "authorization_code", code, code_verifier: verifier });
    expect(result.status).toBe(400);
    expect(result.body.error).toBe("invalid_grant");
  });

  test("a missing code is rejected", async () => {
    const result = await postToken({ grant_type: "authorization_code", redirect_uri: REDIRECT_URI });
    expect(result.status).toBe(400);
    expect(result.body.error).toBe("invalid_grant");
  });

  test("a nonexistent code is rejected", async () => {
    const result = await postToken({
      grant_type: "authorization_code",
      code: "zztest-never-issued",
      redirect_uri: REDIRECT_URI,
      code_verifier: "x",
    });
    expect(result.status).toBe(400);
    expect(result.body.error).toBe("invalid_grant");
  });
});

describe("authorization_code grant (confidential client)", () => {
  test("exchanges a code with the client secret instead of PKCE", async () => {
    const code = await plantAuthCode({ clientId: CONFIDENTIAL_CLIENT_ID });
    const result = await postToken({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_secret: CONFIDENTIAL_CLIENT_SECRET,
    });
    expect(result.status).toBe(200);
    expect(result.body.access_token).toBeString();
    expect(result.body.refresh_token).toBeString();
  });

  test("rejects a wrong client secret", async () => {
    const code = await plantAuthCode({ clientId: CONFIDENTIAL_CLIENT_ID });
    const result = await postToken({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_secret: "wrong",
    });
    expect(result.status).toBe(401);
    expect(result.body.error).toBe("invalid_client");
  });
});
