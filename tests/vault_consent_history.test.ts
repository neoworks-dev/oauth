import { beforeAll, describe, expect, test } from "bun:test";

const staticDirectory = "../handlers/vault/static";
let history: any;

beforeAll(async () => {
  history = await import(`${staticDirectory}/nw-consent-history.js`);
});

const calendar = "@neoworks/calendar";
const photos = "@neoworks/photos";

function earlier(scopes: string[], access: any[] = []) {
  return { firstAuthorizedAt: "2026-01-01T00:00:00Z", lastAuthorizedAt: "2026-02-01T00:00:00Z", scopes, installs: [], access };
}

describe("skipping the consent screen", () => {
  test("a first-party app without share choices skips it", () => {
    expect(history.canSkipConsent({ firstParty: true, history: null }, 0)).toBe(true);
  });

  test("a first-party app that asks to share still shows it", () => {
    expect(history.canSkipConsent({ firstParty: true, history: null }, 1)).toBe(false);
  });

  test("a third-party app never skips it", () => {
    expect(history.canSkipConsent({ firstParty: false, history: null }, 0)).toBe(false);
  });

  test("a third-party app whose scopes were granted before still shows it", () => {
    const returning = { firstParty: false, scopes: [`${calendar}:read`], history: earlier([`${calendar}:read`]) };
    expect(history.canSkipConsent(returning, 0)).toBe(false);
  });

  test("a challenge without the flag counts as third-party", () => {
    expect(history.canSkipConsent({ history: null }, 0)).toBe(false);
  });
});

describe("comparing a request with what the app holds", () => {
  const held = earlier([`${calendar}:read`, `${photos}:read`, `${photos}:write`, "openid"]);

  test("everything is new for an app the user never authorized", () => {
    const classified = history.classifyRequest([`${calendar}:read`, "openid"], null);
    expect(classified).toEqual({ held: [], widened: [], added: [`${calendar}:read`, "openid"] });
  });

  test("held, widened and new scopes are told apart", () => {
    const requested = [`${calendar}:read`, `${calendar}:write`, `${calendar}:share`, `${photos}:read`, "@neoworks/contacts:read", "email"];
    const classified = history.classifyRequest(requested, held);
    expect(classified.held).toEqual([`${calendar}:read`, `${photos}:read`]);
    expect(classified.widened).toEqual([`${calendar}:write`, `${calendar}:share`]);
    expect(classified.added).toEqual(["@neoworks/contacts:read", "email"]);
  });

  test("a share permission on a collection that is not held yet is new, not widened", () => {
    const classified = history.classifyRequest(["@neoworks/contacts:read", "@neoworks/contacts:share"], held);
    expect(classified.added).toEqual(["@neoworks/contacts:read", "@neoworks/contacts:share"]);
  });
});

describe("kept access", () => {
  const held = earlier([`${calendar}:read`, `${photos}:read`, `${photos}:write`]);

  test("held scopes the request no longer asks for are kept", () => {
    expect(history.keptScopes([`${calendar}:read`, `${photos}:read`], held)).toEqual([`${photos}:write`]);
  });

  test("a read is covered by a requested write", () => {
    expect(history.keptScopes([`${calendar}:write`, `${photos}:write`], held)).toEqual([]);
  });

  test("only collections the request does not mention can be revoked", () => {
    expect(history.keptCollections([`${calendar}:read`, `${photos}:read`], held)).toEqual([]);
    expect(history.keptCollections([`${calendar}:read`], held)).toEqual([photos]);
  });

  test("an app never authorized keeps nothing", () => {
    expect(history.keptScopes([`${calendar}:read`], null)).toEqual([]);
  });
});

describe("access by collection", () => {
  test("lists each node once with the highest role", () => {
    const access = [
      { collection: calendar, nodeId: "node-1", role: "read", installId: "install-1" },
      { collection: calendar, nodeId: "node-1", role: "write", installId: "install-2" },
      { collection: calendar, nodeId: "node-2", role: "read", installId: "install-1" },
      { collection: photos, nodeId: "node-3", role: "read", installId: "install-1" },
    ];
    const grouped = history.accessByCollection(earlier([], access));
    expect(grouped[calendar]).toEqual([{ nodeId: "node-1", role: "write" }, { nodeId: "node-2", role: "read" }]);
    expect(grouped[photos]).toEqual([{ nodeId: "node-3", role: "read" }]);
  });

  test("is empty without an earlier authorization", () => {
    expect(history.accessByCollection(null)).toEqual({});
  });
});
