import { beforeAll, describe, expect, test } from "bun:test";
import sodium from "libsodium-wrappers-sumo";

(globalThis as any).sodium = sodium;
const staticDirectory = "../handlers/vault/static";

let primitives: any;
let account: any;
let nodes: any;
let tree: any;
let recovery: any;

beforeAll(async () => {
  await sodium.ready;
  primitives = await import(`${staticDirectory}/nw-primitives.js`);
  account = await import(`${staticDirectory}/nw-account.js`);
  nodes = await import(`${staticDirectory}/nw-nodes.js`);
  tree = await import(`${staticDirectory}/nw-consent-tree.js`);
  recovery = await import(`${staticDirectory}/nw-recovery.js`);
});

// ownerTree builds what GET /vault/tree returns: roots, one container under
// the calendar root and a nested one, with the owner's root grants.
function ownerTree() {
  const identity = account.createIdentity();
  const userId = "user-1";
  const treeNodes: any[] = [];
  const grants: any[] = [];
  const keys: Record<string, Uint8Array> = {};
  for (const collection of nodes.ROOT_COLLECTIONS) {
    const { node, nodeKey } = nodes.createRootNode({ userId, collection, identity });
    treeNodes.push(node);
    keys[collection] = nodeKey;
    const grant = nodes.createGrant({
      nodeId: node.id, nodeKey, epoch: 1, role: "write", principalType: "user", principalId: userId,
      principalEncPub: identity.encPub, granter: { userId, signSec: identity.signSec }, position: nodes.nextLogPosition(null),
    });
    grants.push({ nodeId: node.id, role: "write", epoch: 1, wrappedKeys: grant.wrappedKeys });
  }
  const calendarRoot = treeNodes.find((node) => node.collection === "calendar");
  const work = container("Work", calendarRoot, keys.calendar, userId);
  const nested = container("Projects", work.node, work.key, userId);
  treeNodes.push(work.node, nested.node);
  return { identity, tree: { nodes: treeNodes, grants }, work, nested, calendarRoot };
}

function container(name: string, parent: any, parentKey: Uint8Array, userId: string, baseSeq = 0) {
  const key = primitives.randomBytes(32);
  const node: any = {
    id: crypto.randomUUID(), parentId: parent.id, ownerId: userId, collection: parent.collection, kind: "container",
    epoch: 1, blob: null, deleted: false, baseSeq,
  };
  node.wrappedKey = primitives.encodeBase64Url(nodes.wrapNodeKey(parentKey, key, {
    id: node.id, parentId: parent.id, epoch: 1, parentEpoch: parent.epoch,
  }));
  node.content = [{ facet: 0, ciphertext: primitives.encodeBase64Url(nodes.encryptFacet(key, node, 0, { name })) }];
  return { node, key };
}

describe("consent tree", () => {
  test("opens root keys with the identity and walks down to nested containers", () => {
    const owned = ownerTree();
    const index = tree.buildKeyIndex(owned.tree, owned.identity);
    expect(index.size).toBe(nodes.ROOT_COLLECTIONS.length + 2);
    expect(Buffer.from(index.get(owned.nested.node.id).key).equals(Buffer.from(owned.nested.key))).toBe(true);
  });

  test("reads the name of a container written after its first revision", () => {
    const owned = ownerTree();
    const revised = container("Revised", owned.work.node, owned.work.key, "user-1", 3);
    const extended = { ...owned.tree, nodes: [...owned.tree.nodes, revised.node] };
    const index = tree.buildKeyIndex(extended, owned.identity);
    const described = tree.describeCollections(extended, index, "user-1");
    expect(described.calendar.containers.map((entry: any) => entry.name)).toContain("Revised");
  });

  test("describes collections with readable names and depth", () => {
    const owned = ownerTree();
    const index = tree.buildKeyIndex(owned.tree, owned.identity);
    const described = tree.describeCollections(owned.tree, index, "user-1");
    expect(Object.keys(described).sort()).toEqual(["calendar", "contacts", "files", "google", "photos"]);
    expect(described.calendar.root.name).toBe("Calendar");
    expect(described.calendar.containers.map((entry: any) => [entry.name, entry.depth])).toEqual([["Work", 1], ["Projects", 2]]);
  });

  test("a different identity cannot open any root", () => {
    const owned = ownerTree();
    const stranger = account.createIdentity();
    expect(() => tree.buildKeyIndex(owned.tree, stranger)).toThrow();
  });

  test("whole-collection selection grants the root only", () => {
    const owned = ownerTree();
    const index = tree.buildKeyIndex(owned.tree, owned.identity);
    const collectionTrees = tree.describeCollections(owned.tree, index, "user-1");
    const install = { id: "install-1", encPub: primitives.encodeBase64Url(primitives.boxKeypair().publicKey) };
    const grants = tree.buildInstallGrants({
      selections: { calendar: { whole: true, nodeIds: new Set() } }, collectionTrees, roles: { calendar: "write" },
      index, held: tree.heldRoles(owned.tree, index), userId: "user-1", heads: {}, install, granter: { userId: "user-1", signSec: owned.identity.signSec }, certId: "cert-1",
    });
    expect(grants.length).toBe(1);
    expect(grants[0].nodeId).toBe(owned.calendarRoot.id);
    expect(grants[0].role).toBe("write");
    expect(grants[0].principalId).toBe("install-1");
    expect(grants[0].logIndex).toBe(0);
  });

  test("install grants extend each node's access log head", () => {
    const owned = ownerTree();
    const index = tree.buildKeyIndex(owned.tree, owned.identity);
    const collectionTrees = tree.describeCollections(owned.tree, index, "user-1");
    const install = { id: "install-1", encPub: primitives.encodeBase64Url(primitives.boxKeypair().publicKey) };
    const headHash = primitives.encodeBase64Url(primitives.randomBytes(32));
    const grants = tree.buildInstallGrants({
      selections: { calendar: { whole: true, nodeIds: new Set() } }, collectionTrees, roles: { calendar: "read" },
      index, held: tree.heldRoles(owned.tree, index), userId: "user-1",
      heads: { [owned.calendarRoot.id]: { index: 0, entryHash: headHash } }, install,
      granter: { userId: "user-1", signSec: owned.identity.signSec }, certId: "cert-1",
    });
    expect(grants[0].logIndex).toBe(1);
    expect(grants[0].prevHash).toBe(headHash);
  });

  test("narrowed selection grants only the chosen containers", () => {
    const owned = ownerTree();
    const index = tree.buildKeyIndex(owned.tree, owned.identity);
    const collectionTrees = tree.describeCollections(owned.tree, index, "user-1");
    const install = { id: "install-1", encPub: primitives.encodeBase64Url(primitives.boxKeypair().publicKey) };
    const grants = tree.buildInstallGrants({
      selections: { calendar: { whole: false, nodeIds: new Set([owned.work.node.id]) } }, collectionTrees,
      roles: { calendar: "read" }, index, held: tree.heldRoles(owned.tree, index), userId: "user-1", heads: {}, install,
      granter: { userId: "user-1", signSec: owned.identity.signSec }, certId: "cert-1",
    });
    expect(grants.map((grant: any) => grant.nodeId)).toEqual([owned.work.node.id]);
  });
});

// sharedWithUser adds a root another person owns, sealed to the user with the
// given role, to the owner's tree.
function sharedWithUser(owned: any, role: string) {
  const friend = account.createIdentity();
  const { node, nodeKey } = nodes.createRootNode({ userId: "friend-1", collection: "calendar", identity: friend });
  node.ownerEmail = "friend@example.com";
  const grant = nodes.createGrant({
    nodeId: node.id, nodeKey, epoch: 1, role, principalType: "user", principalId: "user-1",
    principalEncPub: owned.identity.encPub, granter: { userId: "friend-1", signSec: friend.signSec }, position: nodes.nextLogPosition(null),
  });
  owned.tree.nodes.push(node);
  owned.tree.grants.push({ nodeId: node.id, role, epoch: 1, wrappedKeys: grant.wrappedKeys });
  return node;
}

describe("nodes shared with the user", () => {
  test("lists shared entry points apart from the user's own roots", () => {
    const owned = ownerTree();
    const sharedRoot = sharedWithUser(owned, "read");
    const index = tree.buildKeyIndex(owned.tree, owned.identity);
    const described = tree.describeCollections(owned.tree, index, "user-1");
    expect(described.calendar.root.id).toBe(owned.calendarRoot.id);
    const shared = tree.describeSharedNodes(owned.tree, index, "user-1");
    expect(shared.calendar.map((entry: any) => [entry.id, entry.ownerEmail])).toEqual([[sharedRoot.id, "friend@example.com"]]);
  });

  test("a read share is passed to the install as read even when the scope allows write", () => {
    const owned = ownerTree();
    const sharedRoot = sharedWithUser(owned, "read");
    const index = tree.buildKeyIndex(owned.tree, owned.identity);
    const collectionTrees = tree.describeCollections(owned.tree, index, "user-1");
    const install = { id: "install-1", encPub: primitives.encodeBase64Url(primitives.boxKeypair().publicKey) };
    const grants = tree.buildInstallGrants({
      selections: { calendar: { whole: false, nodeIds: new Set([sharedRoot.id]) } }, collectionTrees,
      roles: { calendar: "write" }, index, held: tree.heldRoles(owned.tree, index), userId: "user-1", heads: {}, install,
      granter: { userId: "user-1", signSec: owned.identity.signSec }, certId: "cert-1",
    });
    expect(grants.map((grant: any) => [grant.nodeId, grant.role])).toEqual([[sharedRoot.id, "read"]]);
  });

  test("a write share keeps the write role the scope allows", () => {
    const owned = ownerTree();
    const sharedRoot = sharedWithUser(owned, "write");
    const index = tree.buildKeyIndex(owned.tree, owned.identity);
    const collectionTrees = tree.describeCollections(owned.tree, index, "user-1");
    const install = { id: "install-1", encPub: primitives.encodeBase64Url(primitives.boxKeypair().publicKey) };
    const grants = tree.buildInstallGrants({
      selections: { calendar: { whole: false, nodeIds: new Set([sharedRoot.id]) } }, collectionTrees,
      roles: { calendar: "write" }, index, held: tree.heldRoles(owned.tree, index), userId: "user-1", heads: {}, install,
      granter: { userId: "user-1", signSec: owned.identity.signSec }, certId: "cert-1",
    });
    expect(grants[0].role).toBe("write");
  });
});

describe("recovery words", () => {
  // BIP39 test vectors for 256-bit entropy.
  const vectors: Array<[number, string]> = [
    [0x00, "abandon ".repeat(23) + "art"],
    [0x7f, "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"],
    [0x80, "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless"],
    [0xff, "zoo ".repeat(23) + "vote"],
  ];

  test("matches the BIP39 test vectors", () => {
    for (const [byte, phrase] of vectors) {
      const entropy = new Uint8Array(32).fill(byte);
      expect(recovery.bytesToWords(entropy).join(" ")).toBe(phrase);
      expect(Buffer.from(recovery.parseRecoveryWords(phrase)).equals(Buffer.from(entropy))).toBe(true);
    }
  });

  test("a wrong checksum, word count or unknown word is refused", () => {
    const words = recovery.bytesToWords(new Uint8Array(32));
    expect(words.length).toBe(24);
    expect(() => recovery.wordsToBytes(words.slice(0, 23))).toThrow();
    expect(() => recovery.wordsToBytes([...words.slice(0, 23), "notaword"])).toThrow();
    const swapped = [...words];
    swapped[0] = swapped[0] === "zoo" ? "abandon" : "zoo";
    expect(() => recovery.wordsToBytes(swapped)).toThrow();
  });

  test("parseRecoveryWords accepts mixed separators and case", () => {
    const entropy = primitives.randomBytes(32);
    const words = recovery.bytesToWords(entropy);
    const text = words.map((word: string, position: number) => (position % 2 === 0 ? word.toUpperCase() : word)).join(",\n ");
    expect(Buffer.from(recovery.parseRecoveryWords(text)).equals(Buffer.from(entropy))).toBe(true);
  });

  test("an unknown word is rejected", () => {
    expect(() => recovery.wordsToBytes(["airport", "notaword"])).toThrow();
  });
});
