/** Live integration tests: client_credentials grant on POST /oauth/token. */
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import {
  OAUTH_BASE,
  CONFIDENTIAL_CLIENT_ID,
  CONFIDENTIAL_CLIENT_SECRET,
  PUBLIC_CLIENT_ID,
  REGISTERED_SCOPES,
  postToken,
  clientCredentialsParams,
  verifyAccessToken,
  expectedIssuer,
  setupFixtures,
  teardownFixtures,
} from "./helpers/token_test_helpers";

beforeAll(setupFixtures);
afterAll(teardownFixtures);

describe("client_credentials grant", () => {
  test("issues a token with body credentials", async () => {
    const result = await postToken(clientCredentialsParams("storage:read"));
    expect(result.status).toBe(200);
    expect(result.body.token_type).toBe("Bearer");
    expect(result.body.expires_in).toBe(900);
    expect(result.body.scope).toBe("storage:read");
    expect(result.body.access_token).toBeString();
  });

  test("issues a token with HTTP Basic credentials", async () => {
    const result = await postToken(
      { grant_type: "client_credentials", scope: "storage:read" },
      { basicAuth: [CONFIDENTIAL_CLIENT_ID, CONFIDENTIAL_CLIENT_SECRET] },
    );
    expect(result.status).toBe(200);
    expect(result.body.access_token).toBeString();
  });

  test("never issues a refresh token", async () => {
    const result = await postToken(clientCredentialsParams("storage:read"));
    expect(result.status).toBe(200);
    expect(result.body).not.toContainKey("refresh_token");
  });

  test("token is a valid ES256 JWT with correct claims and no user subject", async () => {
    const result = await postToken(clientCredentialsParams("storage:read"));
    const { payload, protectedHeader } = await verifyAccessToken(result.body.access_token);
    expect(protectedHeader.alg).toBe("ES256");
    expect(payload.iss).toBe(await expectedIssuer());
    expect((payload as any).client_id).toBe(CONFIDENTIAL_CLIENT_ID);
    expect((payload as any).scope).toEqual(["storage:read"]);
    expect(payload.jti).toBeString();
    expect(payload.sub ?? "").toBe("");
    expect((payload.exp as number) - (payload.iat as number)).toBe(900);
  });

  test("sets Cache-Control: no-store on token responses (RFC 6749 §5.1)", async () => {
    const result = await postToken(clientCredentialsParams("storage:read"));
    expect(result.headers.get("cache-control")).toBe("no-store");
  });

  test("rejects a wrong client secret", async () => {
    const result = await postToken({ ...clientCredentialsParams(), client_secret: "wrong" });
    expect(result.status).toBe(401);
    expect(result.body.error).toBe("invalid_client");
  });

  test("rejects an empty client secret", async () => {
    const result = await postToken({ ...clientCredentialsParams(), client_secret: "" });
    expect(result.status).toBe(401);
    expect(result.body.error).toBe("invalid_client");
  });

  test("rejects an unknown client", async () => {
    const result = await postToken({
      grant_type: "client_credentials",
      client_id: "zztest-does-not-exist",
      client_secret: "whatever",
    });
    expect(result.status).toBe(401);
    expect(result.body.error).toBe("invalid_client");
  });

  test("rejects a request with no credentials at all", async () => {
    const result = await postToken({ grant_type: "client_credentials" });
    expect(result.status).toBe(401);
    expect(result.body.error).toBe("invalid_client");
  });

  test("rejects a secretless public client", async () => {
    const result = await postToken({
      grant_type: "client_credentials",
      client_id: PUBLIC_CLIENT_ID,
      client_secret: "anything",
    });
    expect(result.status).toBe(400);
    expect(result.body.error).toBe("unauthorized_client");
  });

  test("rejects mixed identities: body client_id with another client's Basic credentials", async () => {
    const result = await postToken(
      { grant_type: "client_credentials", client_id: CONFIDENTIAL_CLIENT_ID },
      { basicAuth: ["some-other-client", "some-other-secret"] },
    );
    expect(result.status).toBe(401);
    expect(result.body.error).toBe("invalid_client");
  });

  test("rejects scopes outside the client registration", async () => {
    const result = await postToken(clientCredentialsParams("admin:everything"));
    expect(result.status).toBe(400);
    expect(result.body.error).toBe("invalid_scope");
  });

  test("rejects a mix of registered and unregistered scopes", async () => {
    const result = await postToken(clientCredentialsParams("storage:read admin:everything"));
    expect(result.status).toBe(400);
    expect(result.body.error).toBe("invalid_scope");
  });

  test("an omitted scope defaults to the full registered scope list", async () => {
    const result = await postToken(clientCredentialsParams());
    expect(result.status).toBe(200);
    expect(result.body.scope.split(" ").sort()).toEqual([...REGISTERED_SCOPES].sort());
  });

  test("token passes introspection as active", async () => {
    const issued = await postToken(clientCredentialsParams("storage:read"));
    const response = await fetch(`${OAUTH_BASE}/oauth/introspect`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${issued.body.access_token}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ token: issued.body.access_token }).toString(),
    });
    expect(response.status).toBe(200);
    const introspection = (await response.json()) as any;
    expect(introspection.active).toBe(true);
    expect(introspection.client_id).toBe(CONFIDENTIAL_CLIENT_ID);
    expect(introspection.sub).toBe("");
  });
});
