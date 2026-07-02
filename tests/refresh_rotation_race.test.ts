/**
 * Live concurrency tests for refresh-token rotation.
 *
 * Rotation is protected by a Redis lock plus a short grace-window cache
 * (AcquireRotationLock / GetRotationResult / awaitRotationResult in the token
 * handler). These tests fire many refreshes of the same token simultaneously
 * and assert the two properties that matter under load: no token loss (every
 * concurrent caller gets a usable result) and no split-brain (they all converge
 * on a single rotated token family, never two).
 */
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import {
  redis,
  postToken,
  exchangeFreshAuthCode,
  setupFixtures,
  teardownFixtures,
} from "./helpers/token_test_helpers";

beforeAll(setupFixtures);
afterAll(teardownFixtures);

function refresh(refreshToken: string) {
  return postToken({ grant_type: "refresh_token", refresh_token: refreshToken });
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

describe("refresh rotation under concurrency", () => {
  test("N simultaneous refreshes of one token converge on a single new token family", async () => {
    const exchanged = await exchangeFreshAuthCode();
    const original = exchanged.body.refresh_token;

    const CONCURRENCY = 12;
    const responses = await Promise.all(Array.from({ length: CONCURRENCY }, () => refresh(original)));

    // No token loss: every concurrent caller gets a 200, not a spurious reject.
    for (const response of responses) {
      expect(response.status).toBe(200);
    }

    // No split-brain: they all share one rotated access + refresh token.
    const accessTokens = unique(responses.map((r) => r.body.access_token));
    const refreshTokens = unique(responses.map((r) => r.body.refresh_token));
    expect(accessTokens).toHaveLength(1);
    expect(refreshTokens).toHaveLength(1);

    // The single surviving token is genuinely new and usable.
    const rotated = refreshTokens[0];
    expect(rotated).not.toBe(original);
    const next = await refresh(rotated);
    expect(next.status).toBe(200);
    expect(next.body.refresh_token).not.toBe(rotated);
  });

  test("concurrent refreshes never mint two different usable descendants", async () => {
    const exchanged = await exchangeFreshAuthCode();
    const original = exchanged.body.refresh_token;

    const responses = await Promise.all(Array.from({ length: 8 }, () => refresh(original)));
    const distinctDescendants = unique(
      responses.filter((r) => r.status === 200).map((r) => r.body.refresh_token),
    );
    expect(distinctDescendants).toHaveLength(1);

    // Before the replay, the single descendant is the live token.
    const descendantBeforeReplay = await refresh(distinctDescendants[0]);
    expect(descendantBeforeReplay.status).toBe(200);
    const grandchild = descendantBeforeReplay.body.refresh_token;

    // Drop the grace cache so the original reads as a genuine post-grace replay.
    // That is treated as token theft: the whole grant is revoked, which must
    // kill every descendant too — not just reject the replayed token.
    await redis.send("DEL", [`rt_result:${original}`]);
    const replayOriginal = await refresh(original);
    expect(replayOriginal.status).toBe(400);
    expect(replayOriginal.body.error).toBe("invalid_grant");

    const grandchildAfterReplay = await refresh(grandchild);
    expect(grandchildAfterReplay.status).toBe(400);
    expect(grandchildAfterReplay.body.error).toBe("invalid_grant");
  });

  test("a burst of refreshes across two rotation generations stays single-threaded", async () => {
    const exchanged = await exchangeFreshAuthCode();
    let current = exchanged.body.refresh_token;

    // Two sequential generations, each hit concurrently.
    for (let generation = 0; generation < 2; generation++) {
      const responses = await Promise.all(Array.from({ length: 6 }, () => refresh(current)));
      for (const response of responses) {
        expect(response.status).toBe(200);
      }
      const next = unique(responses.map((r) => r.body.refresh_token));
      expect(next).toHaveLength(1);
      expect(next[0]).not.toBe(current);
      current = next[0];
    }
  });
});
