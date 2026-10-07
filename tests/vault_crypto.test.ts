import { beforeAll, describe, expect, test } from "bun:test";
import sodium from "libsodium-wrappers-sumo";

const staticDirectory = "../handlers/vault/static";
// The modules read the global libsodium, exactly as in the browser.
(globalThis as any).sodium = sodium;

let primitives: any;
let account: any;
let nodes: any;

beforeAll(async () => {
  await sodium.ready;
  primitives = await import(`${staticDirectory}/nw-primitives.js`);
  account = await import(`${staticDirectory}/nw-account.js`);
  nodes = await import(`${staticDirectory}/nw-nodes.js`);
});

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

describe("tlv", () => {
  test("frames the context, a zero byte and length-prefixed fields", () => {
    const framed = primitives.tlv("ab", primitives.fieldString("x"), primitives.fieldU32(7));
    expect(hex(framed)).toBe("616200" + "00000001" + "78" + "00000004" + "00000007");
  });

  test("an absent optional is a zero-length field", () => {
    const framed = primitives.tlv("c", primitives.absentField, primitives.fieldU8(1));
    expect(hex(framed)).toBe("6300" + "00000000" + "00000001" + "01");
  });

  test("u64 is eight bytes big-endian", () => {
    expect(hex(primitives.fieldU64(258))).toBe("0000000000000102");
  });
});

describe("password split", () => {
  const params = { salt: "AAAAAAAAAAAAAAAAAAAAAA", ops: 1, mem: 8192 };

  test("authKey and passwordKEK are independent and deterministic", () => {
    const first = account.derivePasswordKeys("correct horse", params);
    const second = account.derivePasswordKeys("correct horse", params);
    expect(hex(first.authKey)).toBe(hex(second.authKey));
    expect(hex(first.passwordKEK)).toBe(hex(second.passwordKEK));
    expect(hex(first.authKey)).not.toBe(hex(first.passwordKEK));
    expect(first.authKey.length).toBe(32);
  });

  test("a different password or salt changes both keys", () => {
    const base = account.derivePasswordKeys("correct horse", params);
    const otherPassword = account.derivePasswordKeys("wrong horse", params);
    const otherSalt = account.derivePasswordKeys("correct horse", { ...params, salt: "AAAAAAAAAAAAAAAAAAAAAQ" });
    expect(hex(otherPassword.authKey)).not.toBe(hex(base.authKey));
    expect(hex(otherSalt.passwordKEK)).not.toBe(hex(base.passwordKEK));
  });
});

describe("AMK wraps", () => {
  test("unwrap succeeds only with the right key, user and purpose", () => {
    const amk = primitives.randomBytes(32);
    const kek = primitives.randomBytes(32);
    const wrapped = account.wrapAmk(kek, amk, "user-1", "password");
    expect(hex(account.unwrapAmk(kek, wrapped, "user-1", "password"))).toBe(hex(amk));
    expect(() => account.unwrapAmk(kek, wrapped, "user-2", "password")).toThrow();
    expect(() => account.unwrapAmk(kek, wrapped, "user-1", "recovery")).toThrow();
    expect(() => account.unwrapAmk(primitives.randomBytes(32), wrapped, "user-1", "password")).toThrow();
  });

  test("the identity round-trips and is bound to the bundle version", () => {
    const amk = primitives.randomBytes(32);
    const identity = account.createIdentity();
    const bundle = account.buildBundle({
      userId: "user-1", version: 1, amk, identity,
      passwordKek: primitives.randomBytes(32), recoveryKek: primitives.randomBytes(32),
    });
    const opened = account.unwrapIdentity(amk, { ...bundle, userId: "user-1" });
    expect(hex(opened.encSec)).toBe(hex(identity.encSec));
    expect(hex(opened.signSec)).toBe(hex(identity.signSec));
    expect(() => account.unwrapIdentity(amk, { ...bundle, userId: "user-1", version: 2 })).toThrow();
  });

  test("selfSig verifies over tlv of the public keys", () => {
    const identity = account.createIdentity();
    const signature = account.signIdentity(identity, "user-1");
    const message = account.identityMessage("user-1", identity.encPub, identity.signPub);
    expect(primitives.verify(identity.signPub, message, signature)).toBe(true);
  });
});

describe("nodes", () => {
  test("a root carries no content", () => {
    const identity = account.createIdentity();
    const { node } = nodes.createRootNode({ userId: "user-1", collection: "@neoworks/calendar", identity });
    expect(node).toMatchObject({ content: "", blob: null, targetId: null, targetRole: null, wrappedKey: null });
  });

  test("a facet decrypts with its node key, tag and position and nothing else", () => {
    const key = primitives.randomBytes(32);
    const node = { id: "node-1", collection: "@neoworks/calendar", epoch: 1, baseSeq: 0, deleted: false };
    const plaintext = Uint8Array.from([0x0a, 0x03, 0x61, 0x62, 0x63]);
    const ciphertext = nodes.encryptFacet(key, node, 488337835, plaintext);
    expect(ciphertext.length % 256).toBe(24 + 16);
    expect(Buffer.from(nodes.decryptFacet(key, node, 488337835, ciphertext)).equals(Buffer.from(plaintext))).toBe(true);
    expect(() => nodes.decryptFacet(key, node, 1, ciphertext)).toThrow();
    expect(() => nodes.decryptFacet(key, { ...node, epoch: 2 }, 488337835, ciphertext)).toThrow();
    expect(() => nodes.decryptFacet(primitives.randomBytes(32), node, 488337835, ciphertext)).toThrow();
  });

  test("content frames facets by ascending tag and parses back", () => {
    const facets = [{ tag: 488337835, ciphertext: Uint8Array.from([7, 8]) }, { tag: 1, ciphertext: Uint8Array.from([9]) }];
    const parsed = nodes.parseContent(nodes.assembleContent(facets));
    expect(parsed.map((entry: any) => [entry.tag, Array.from(entry.ciphertext)])).toEqual([[1, [9]], [488337835, [7, 8]]]);
    expect(() => nodes.parseContent(Uint8Array.from([0x08, 0x01]))).toThrow();
  });

  test("the root signature verifies over the write message", () => {
    const identity = account.createIdentity();
    const { node } = nodes.createRootNode({ userId: "user-1", collection: "@neoworks/files", identity });
    const signature = primitives.decodeBase64Url(node.signature);
    expect(primitives.verify(identity.signPub, nodes.nodeWriteMessage(node), signature)).toBe(true);
    expect(primitives.verify(identity.signPub, nodes.nodeWriteMessage({ ...node, epoch: 2 }), signature)).toBe(false);
  });

  test("child keys wrap under the parent key and the node identity", () => {
    const parentKey = primitives.randomBytes(32);
    const nodeKey = primitives.randomBytes(32);
    const info = { id: "child", parentId: "parent", epoch: 1, parentEpoch: 1 };
    const wrapped = nodes.wrapNodeKey(parentKey, nodeKey, info);
    expect(hex(nodes.unwrapNodeKey(parentKey, wrapped, info))).toBe(hex(nodeKey));
    expect(() => nodes.unwrapNodeKey(parentKey, wrapped, { ...info, id: "other" })).toThrow();
  });

  test("a grant seals the node key to the principal and signs its log entry", () => {
    const owner = account.createIdentity();
    const recipient = primitives.boxKeypair();
    const nodeKey = primitives.randomBytes(32);
    const grant = nodes.createGrant({
      nodeId: "node-1", nodeKey, epoch: 1, role: "read", principalType: "install", principalId: "install-1",
      principalEncPub: recipient.publicKey, granter: { userId: "user-1", signSec: owner.signSec }, certId: "cert-1",
      position: nodes.nextLogPosition(null),
    });
    const wrappedKeys = primitives.decodeBase64Url(grant.wrappedKeys);
    const opened = primitives.sealOpen(recipient.publicKey, recipient.secretKey, wrappedKeys);
    expect(hex(opened)).toBe(hex(nodeKey));
    const entryBytes = nodes.accessEntryBytes({
      ...grant, index: grant.logIndex, prevHash: primitives.decodeBase64Url(grant.prevHash), action: "grant",
      wrappedKeysHash: primitives.hash(wrappedKeys), actorType: "user", actorId: "user-1",
    });
    expect(primitives.verify(owner.signPub, entryBytes, primitives.decodeBase64Url(grant.signature))).toBe(true);
    expect(grant.certId).toBe("cert-1");
  });

  test("a certificate signature covers the exact JSON bytes", () => {
    const owner = account.createIdentity();
    const install = { id: "install-1", encPub: "AAAA", signPub: "BBBB" };
    const built = nodes.buildCertificate({
      userId: "user-1", clientId: "app", install, scopes: ["calendar:read"], signSec: owner.signSec, lifetimeMs: 3600_000,
    });
    const bytes = primitives.decodeBase64Url(built.certificate);
    const signature = primitives.decodeBase64Url(built.certificateSignature);
    expect(primitives.verify(owner.signPub, nodes.delegationMessage(bytes), signature)).toBe(true);
    const document = JSON.parse(new TextDecoder().decode(bytes));
    expect(document.v).toBe(1);
    expect(document.installId).toBe("install-1");
    expect(document.expiresAt).toMatch(/Z$/);
  });
});
