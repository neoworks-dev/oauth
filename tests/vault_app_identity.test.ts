import { beforeAll, describe, expect, test } from "bun:test";

const staticDirectory = "../handlers/vault/static";
let identity: any;

beforeAll(async () => {
  identity = await import(`${staticDirectory}/nw-app-identity.js`);
});

const acme = { handle: "acme", kind: "organization", displayName: "Acme", verified: false };

describe("the badge of an app without a logo", () => {
  test("shows the first letters of the first two words", () => {
    expect(identity.initialsOf("Recipe Box")).toBe("RB");
    expect(identity.initialsOf("recipes")).toBe("R");
    expect(identity.initialsOf("Über-Cool App Name")).toBe("ÜC");
  });

  test("falls back to a question mark for a name without letters", () => {
    expect(identity.initialsOf("")).toBe("?");
    expect(identity.initialsOf("---")).toBe("?");
  });

  test("derives the same colour from the same client id", () => {
    expect(identity.colourFor("acme-recipes")).toBe(identity.colourFor("acme-recipes"));
    expect(identity.colourFor("acme-recipes")).not.toBe(identity.colourFor("acme-recipes-2"));
    expect(identity.colourFor("acme-recipes")).toMatch(/^hsl\(\d+ 55% 38%\)$/);
  });
});

describe("who is behind an app", () => {
  test("names the owner with the handle", () => {
    expect(identity.ownerLine({ owner: acme })).toBe("Published by Acme (@acme).");
  });

  test("marks organizations Neoworks verified", () => {
    expect(identity.ownerText({ ...acme, verified: true })).toBe("Acme (@acme), verified organization");
  });

  test("says so when nobody owns the app", () => {
    expect(identity.ownerLine({ owner: null })).toBe("Publisher unknown.");
  });

  test("finds the owner of the scope a collection lives in", () => {
    expect(identity.collectionOwner("@acme/recipes", { acme })).toEqual(acme);
    expect(identity.collectionOwner("@acme/recipes", {})).toBeNull();
    expect(identity.collectionOwner("@acme/recipes", undefined)).toBeNull();
  });
});

describe("whether the app is verified", () => {
  test("a first-party app is made by Neoworks", () => {
    expect(identity.verificationNotice({ firstParty: true }).state).toBe("first-party");
  });

  test("a third-party app with proven domains is verified by its owner", () => {
    const notice = identity.verificationNotice({ firstParty: false, verified: true, owner: acme });
    expect(notice.state).toBe("verified");
    expect(notice.text).toContain("verified by Acme (@acme)");
  });

  test("anything else is unverified, also when the flag is set but nobody owns the app", () => {
    expect(identity.verificationNotice({ firstParty: false, verified: false, owner: acme }).state).toBe("unverified");
    expect(identity.verificationNotice({ firstParty: false, verified: true, owner: null }).state).toBe("unverified");
    expect(identity.verificationNotice({}).text).toContain("not verified");
  });

  test("only approved third-party apps show the review notice", () => {
    expect(identity.reviewNotice({ firstParty: false, reviewStatus: "approved" })).toContain("Neoworks");
    expect(identity.reviewNotice({ firstParty: false, reviewStatus: "pending" })).toBeNull();
    expect(identity.reviewNotice({ firstParty: true, reviewStatus: "approved" })).toBeNull();
  });
});
