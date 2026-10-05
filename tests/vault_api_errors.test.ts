import { describe, expect, test } from "bun:test";

const { ApiError, describeError, isChallengeGone } = await import("../handlers/vault/static/nw-api.js");

describe("authorization request errors", () => {
  test("an expired request tells the user to start again from the app", () => {
    const error = new ApiError(404, "challenge_not_found");
    expect(isChallengeGone(error)).toBe(true);
    expect(describeError(error)).toContain("start again");
  });

  test("a used request is not retryable either", () => {
    const error = new ApiError(409, "challenge_used");
    expect(isChallengeGone(error)).toBe(true);
    expect(describeError(error)).toContain("start again");
  });

  test("other errors stay retryable", () => {
    expect(isChallengeGone(new ApiError(500, "internal"))).toBe(false);
  });
});
