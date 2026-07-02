/** Live integration tests: refresh_token grant — rotation, grace window, replay. */
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import {
  redis,
  postToken,
  plantRefreshToken,
  exchangeFreshAuthCode,
  setupFixtures,
  teardownFixtures,
} from "./helpers/token_test_helpers";

beforeAll(setupFixtures);
afterAll(teardownFixtures);

describe("refresh_token grant", () => {
  test("rotates: new access token, new refresh token, same scope", async () => {
    const exchanged = await exchangeFreshAuthCode();
    const oldRefreshToken = exchanged.body.refresh_token;
    const rotated = await postToken({ grant_type: "refresh_token", refresh_token: oldRefreshToken });
    expect(rotated.status).toBe(200);
    expect(rotated.body.access_token).toBeString();
    expect(rotated.body.refresh_token).toBeString();
    expect(rotated.body.refresh_token).not.toBe(oldRefreshToken);
    expect(rotated.body.scope).toBe("storage:read");
  });

  test("re-sending the old token inside the grace window returns the cached rotation result", async () => {
    const exchanged = await exchangeFreshAuthCode();
    const oldRefreshToken = exchanged.body.refresh_token;
    const rotated = await postToken({ grant_type: "refresh_token", refresh_token: oldRefreshToken });
    const replayed = await postToken({ grant_type: "refresh_token", refresh_token: oldRefreshToken });
    expect(replayed.status).toBe(200);
    expect(replayed.body.access_token).toBe(rotated.body.access_token);
    expect(replayed.body.refresh_token).toBe(rotated.body.refresh_token);
  });

  test("a genuine replay after the grace window revokes the whole grant", async () => {
    const exchanged = await exchangeFreshAuthCode();
    const oldRefreshToken = exchanged.body.refresh_token;
    const rotated = await postToken({ grant_type: "refresh_token", refresh_token: oldRefreshToken });
    expect(rotated.status).toBe(200);
    // Simulate the grace window expiring instead of sleeping 60s.
    await redis.send("DEL", [`rt_result:${oldRefreshToken}`]);
    const replay = await postToken({ grant_type: "refresh_token", refresh_token: oldRefreshToken });
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe("invalid_grant");
    // Replay detection must kill the rotated descendant too.
    const descendant = await postToken({ grant_type: "refresh_token", refresh_token: rotated.body.refresh_token });
    expect(descendant.status).toBe(400);
    expect(descendant.body.error).toBe("invalid_grant");
  });

  test("rejects a revoked refresh token", async () => {
    const jti = await plantRefreshToken({ revoked: true });
    const result = await postToken({ grant_type: "refresh_token", refresh_token: jti });
    expect(result.status).toBe(400);
    expect(result.body.error).toBe("invalid_grant");
  });

  test("rejects an expired refresh token", async () => {
    const jti = await plantRefreshToken({ expiresInSeconds: -60 });
    const result = await postToken({ grant_type: "refresh_token", refresh_token: jti });
    expect(result.status).toBe(400);
    expect(result.body.error).toBe("invalid_grant");
  });

  test("rejects an unknown refresh token", async () => {
    const result = await postToken({ grant_type: "refresh_token", refresh_token: "zztest-never-issued" });
    expect(result.status).toBe(400);
    expect(result.body.error).toBe("invalid_grant");
  });

  test("rejects a missing refresh_token parameter", async () => {
    const result = await postToken({ grant_type: "refresh_token" });
    expect(result.status).toBe(400);
    expect(result.body.error).toBe("invalid_grant");
  });
});
