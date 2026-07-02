/** Live integration tests: grant dispatch and hostile input on POST /oauth/token. */
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import {
  OAUTH_BASE,
  CONFIDENTIAL_CLIENT_ID,
  CONFIDENTIAL_CLIENT_SECRET,
  surql,
  postToken,
  setupFixtures,
  teardownFixtures,
} from "./helpers/token_test_helpers";

beforeAll(setupFixtures);
afterAll(teardownFixtures);

describe("grant dispatch and hostile input", () => {
  test("rejects an unsupported grant type", async () => {
    const result = await postToken({ grant_type: "password" });
    expect(result.status).toBe(400);
    expect(result.body.error).toBe("unsupported_grant_type");
  });

  test("rejects a missing grant type", async () => {
    const result = await postToken({});
    expect(result.status).toBe(400);
    expect(result.body.error).toBe("unsupported_grant_type");
  });

  test("rejects GET requests", async () => {
    const result = await postToken({}, { method: "GET" });
    expect(result.status).toBe(405);
  });

  test("SurrealQL metacharacters in client_id do not error or damage the client table", async () => {
    const before = (await surql("SELECT count() FROM client GROUP ALL;"))[0].result[0].count;
    const result = await postToken({
      grant_type: "client_credentials",
      client_id: '"; DELETE client; SELECT * FROM client WHERE id = "',
      client_secret: "x",
    });
    expect(result.status).toBe(401);
    expect(result.body.error).toBe("invalid_client");
    const after = (await surql("SELECT count() FROM client GROUP ALL;"))[0].result[0].count;
    expect(after).toBe(before);
  });

  test("an oversized client_id fails cleanly, not with a 500", async () => {
    const result = await postToken({
      grant_type: "client_credentials",
      client_id: "A".repeat(100_000),
      client_secret: "x",
    });
    expect(result.status).toBeGreaterThanOrEqual(400);
    expect(result.status).toBeLessThan(500);
  });

  test("an oversized secret fails cleanly (bcrypt 72-byte limit)", async () => {
    const result = await postToken({
      grant_type: "client_credentials",
      client_id: CONFIDENTIAL_CLIENT_ID,
      client_secret: CONFIDENTIAL_CLIENT_SECRET + "A".repeat(100_000),
    });
    expect(result.status).toBe(401);
    expect(result.body.error).toBe("invalid_client");
  });

  test("a non-form body fails cleanly", async () => {
    const result = await postToken(
      {},
      { rawBody: '{"grant_type": "client_credentials"}', contentType: "application/json" },
    );
    expect(result.status).toBe(400);
  });

  test("error responses never leak whether the client exists vs the secret being wrong", async () => {
    const unknownClient = await postToken({
      grant_type: "client_credentials",
      client_id: "zztest-does-not-exist",
      client_secret: "x",
    });
    const wrongSecret = await postToken({
      grant_type: "client_credentials",
      client_id: CONFIDENTIAL_CLIENT_ID,
      client_secret: "wrong",
    });
    expect(unknownClient.status).toBe(wrongSecret.status);
    expect(unknownClient.body).toEqual(wrongSecret.body);
  });

  test("discovery document advertises exactly the implemented grants", async () => {
    const response = await fetch(`${OAUTH_BASE}/.well-known/openid-configuration`);
    const discovery = (await response.json()) as any;
    expect(discovery.grant_types_supported.sort()).toEqual(
      ["authorization_code", "client_credentials", "refresh_token"].sort(),
    );
    expect(discovery.code_challenge_methods_supported).toEqual(["S256"]);
  });
});
