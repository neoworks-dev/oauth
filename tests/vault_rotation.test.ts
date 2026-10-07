import { beforeAll, describe, expect, test } from "bun:test";
import sodium from "libsodium-wrappers-sumo";

(globalThis as any).sodium = sodium;
const staticDirectory = "../handlers/vault/static";

let primitives: any;
let account: any;
let nodes: any;
let rotation: any;

beforeAll(async () => {
  await sodium.ready;
  primitives = await import(`${staticDirectory}/nw-primitives.js`);
  account = await import(`${staticDirectory}/nw-account.js`);
  nodes = await import(`${staticDirectory}/nw-nodes.js`);
  rotation = await import(`${staticDirectory}/nw-rotation.js`);
});

const userId = "11111111-1111-4111-8111-111111111111";
const collections = ["@neoworks/calendar", "@neoworks/contacts"];

// ownTree is what GET /vault/tree returns for a user whose roots are sealed to
// the given identity.
function ownTree(identity: any) {
  const treeNodes: any[] = [];
  const grants: any[] = [];
  const keys: Record<string, Uint8Array> = {};
  const heads: Record<string, any> = {};
  for (const collection of collections) {
    const { node, nodeKey } = nodes.createRootNode({ userId, collection, identity });
    const grant = nodes.createGrant({
      nodeId: node.id, nodeKey, epoch: 1, role: "write", principalType: "user", principalId: userId,
      principalEncPub: identity.encPub, granter: { userId, signSec: identity.signSec }, position: nodes.nextLogPosition(null),
    });
    treeNodes.push(node);
    keys[node.id] = nodeKey;
    grants.push({ nodeId: node.id, role: "write", epoch: 1, wrappedKeys: grant.wrappedKeys });
    heads[node.id] = { index: 0, entryHash: primitives.encodeBase64Url(primitives.hash(nodes.accessEntryBytes({
      nodeId: node.id, index: 0, prevHash: grant.prevHash ? primitives.decodeBase64Url(grant.prevHash) : nodes.GENESIS_PREV_HASH,
      action: "grant", principalType: "user", principalId: userId, role: "write", facets: null, epoch: 1,
      wrappedKeysHash: primitives.hash(primitives.decodeBase64Url(grant.wrappedKeys)), actorType: "user", actorId: userId, certId: null,
    }))) };
  }
  return { tree: { nodes: treeNodes, grants, heads }, keys };
}

describe("previous identity", () => {
  test("is wrapped under the new AMK and opens with it", () => {
    const previous = account.createIdentity();
    const amk = primitives.randomBytes(32);
    const payload = rotation.previousIdentityPayload({ amk, previousIdentity: previous, userId, version: 2 });
    const opened = rotation.openPreviousIdentity(amk, { userId, version: 2, previous: payload });
    expect(Buffer.from(opened.encSec).equals(Buffer.from(previous.encSec))).toBe(true);
    expect(Buffer.from(opened.signSec).equals(Buffer.from(previous.signSec))).toBe(true);
    expect(rotation.openPreviousIdentity(amk, { userId, version: 2, previous: null })).toBeNull();
  });

  test("does not open with another AMK or bundle version", () => {
    const previous = account.createIdentity();
    const amk = primitives.randomBytes(32);
    const payload = rotation.previousIdentityPayload({ amk, previousIdentity: previous, userId, version: 2 });
    expect(() => rotation.openPreviousIdentity(primitives.randomBytes(32), { userId, version: 2, previous: payload })).toThrow();
    expect(() => rotation.openPreviousIdentity(amk, { userId, version: 3, previous: payload })).toThrow();
  });
});

describe("resealing own grants", () => {
  test("seals every own root key to the new identity as the next log entry", () => {
    const previous = account.createIdentity();
    const next = account.createIdentity();
    const { tree, keys } = ownTree(previous);
    const requests = rotation.resealOwnGrants({ tree, userId, previousIdentity: previous, identity: next });
    expect(requests.length).toBe(collections.length);
    for (const request of requests) {
      const sealed = primitives.decodeBase64Url(request.body.grant.wrappedKeys);
      const key = primitives.sealOpen(next.encPub, next.encSec, sealed);
      expect(Buffer.from(key).equals(Buffer.from(keys[request.nodeId]))).toBe(true);
      expect(request.body.entry.index).toBe(1);
      expect(request.body.entry.prevHash).toBe(tree.heads[request.nodeId].entryHash);
      expect(request.body.entry.actorId).toBe(userId);
      expect(request.body.entry.wrappedKeysHash).toBe(primitives.encodeBase64Url(primitives.hash(sealed)));
    }
  });

  test("leaves grants other people made on their nodes alone", () => {
    const previous = account.createIdentity();
    const next = account.createIdentity();
    const { tree } = ownTree(previous);
    tree.nodes.push({ id: "foreign-root", ownerId: "someone-else", kind: "root", collection: "@neoworks/calendar" });
    tree.grants.push({ nodeId: "foreign-root", role: "read", epoch: 1, wrappedKeys: "irrelevant" });
    const requests = rotation.resealOwnGrants({ tree, userId, previousIdentity: previous, identity: next });
    expect(requests.map((request: any) => request.nodeId)).not.toContain("foreign-root");
  });
});
