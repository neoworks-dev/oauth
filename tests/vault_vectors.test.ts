// Reproduces the contract test vectors (packages/libneoworks/test-vectors/v1.json)
// with the account vault's JavaScript. The suite is skipped when the vectors are
// not checked out next to this repository.
import { beforeAll, describe, expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import sodium from "libsodium-wrappers-sumo";

const vectorsPath = new URL("../../../packages/libneoworks/test-vectors/v1.json", import.meta.url).pathname;
const staticDirectory = "../handlers/vault/static";
(globalThis as any).sodium = sodium;

const available = existsSync(vectorsPath);
const run = available ? describe : describe.skip;

let vectors: any;
let primitives: any;
let account: any;
let nodes: any;

const fromHex = (text: string): Uint8Array => sodium.from_hex(text);
const hex = (bytes: Uint8Array): string => sodium.to_hex(bytes);

beforeAll(async () => {
  await sodium.ready;
  if (!available) {
    return;
  }
  vectors = JSON.parse(readFileSync(vectorsPath, "utf8"));
  primitives = await import(`${staticDirectory}/nw-primitives.js`);
  account = await import(`${staticDirectory}/nw-account.js`);
  nodes = await import(`${staticDirectory}/nw-nodes.js`);
});

function tlvField(field: any): Uint8Array {
  if (field.type === "text") return primitives.fieldString(field.value);
  if (field.type === "bytes") return fromHex(field.hex);
  if (field.type === "u8") return primitives.fieldU8(field.value);
  if (field.type === "u32") return primitives.fieldU32(field.value);
  if (field.type === "u64") return primitives.fieldU64(field.value);
  return primitives.absentField;
}

run("contract vectors", () => {
  test("tlv", () => {
    for (const entry of vectors.tlv) {
      expect(hex(primitives.tlv(entry.context, ...entry.fields.map(tlvField)))).toBe(entry.expectedHex);
    }
  });

  test("kdf, hash and pad", () => {
    for (const entry of vectors.kdf) {
      expect(hex(primitives.kdf(fromHex(entry.keyHex), entry.id, entry.context))).toBe(entry.expectedHex);
    }
    for (const entry of vectors.hash) {
      expect(hex(primitives.hash(primitives.utf8(entry.inputUtf8)))).toBe(entry.expectedHex);
    }
    for (const entry of vectors.pad) {
      expect(hex(primitives.pad(fromHex(entry.inputHex)))).toBe(entry.paddedHex);
    }
  });

  test("aead opens the vector and rejects other aad", () => {
    const v = vectors.aead;
    const opened = primitives.aeadOpen(fromHex(v.keyHex), fromHex(v.boxedHex), fromHex(v.aadHex));
    expect(hex(opened)).toBe(v.plaintextHex);
    expect(() => primitives.aeadOpen(fromHex(v.keyHex), fromHex(v.boxedHex), primitives.utf8("other"))).toThrow();
  });

  test("seal opens the vector", () => {
    const v = vectors.seal;
    const opened = primitives.sealOpen(fromHex(v.recipientEncPubHex), fromHex(v.recipientEncSecHex), fromHex(v.sealedHex));
    expect(hex(opened)).toBe(v.plaintextHex);
  });

  test("password split reproduces authKey and passwordKEK", () => {
    const v = vectors.account;
    const keys = account.derivePasswordKeys(v.passwordUtf8, {
      salt: primitives.encodeBase64Url(fromHex(v.pwhashSaltHex)), ops: v.pwhashOpsLimit, mem: v.pwhashMemLimit,
    });
    expect(hex(keys.authKey)).toBe(v.authKeyHex);
    expect(hex(keys.passwordKEK)).toBe(v.passwordKekHex);
    expect(hex(account.deriveRecoveryKek(fromHex(v.recoveryEntropyHex)))).toBe(v.recoveryKekHex);
  });

  test("AMK wraps and identity open with the vault's AAD", () => {
    const v = vectors.account;
    expect(hex(account.amkAad(v.userId, "password"))).toBe(v.amkPasswordAadHex);
    expect(hex(account.amkAad(v.userId, "recovery"))).toBe(v.amkRecoveryAadHex);
    expect(hex(account.identityAad(v.userId, v.bundleVersion))).toBe(v.identityPrivateAadHex);
    const fromPassword = account.unwrapAmk(fromHex(v.passwordKekHex), fromHex(v.amkPasswordHex), v.userId, "password");
    const fromRecovery = account.unwrapAmk(fromHex(v.recoveryKekHex), fromHex(v.amkRecoveryHex), v.userId, "recovery");
    expect(hex(fromPassword)).toBe(v.amkHex);
    expect(hex(fromRecovery)).toBe(v.amkHex);
    const identity = account.unwrapIdentity(fromHex(v.amkHex), v.bundleJson);
    expect(hex(identity.encSec)).toBe(v.encSecHex);
    expect(hex(identity.signSec)).toBe(v.signSecHex);
  });

  test("selfSig is reproduced", () => {
    const v = vectors.account;
    const identity = { encPub: fromHex(v.encPubHex), signPub: fromHex(v.signPubHex), signSec: fromHex(v.signSecHex) };
    expect(hex(account.identityMessage(v.userId, identity.encPub, identity.signPub))).toBe(v.selfSigMessageHex);
    expect(hex(account.signIdentity(identity, v.userId))).toBe(v.selfSigHex);
  });

  test("node key wrap, facets and write signature", () => {
    const v = vectors.node;
    const node = v.nodeJson;
    const info = { id: node.id, parentId: node.parentId, epoch: node.epoch, parentEpoch: v.parentEpoch };
    expect(hex(nodes.nodeKeyAad(info))).toBe(v.wrappedKeyAadHex);
    const unwrapped = nodes.unwrapNodeKey(fromHex(v.rootNodeKeyHex), primitives.decodeBase64Url(node.wrappedKey), info);
    expect(hex(unwrapped)).toBe(v.itemNodeKeyHex);
    node.content.forEach((entry: any, position: number) => {
      const aad = nodes.contentAad({ id: node.id, collection: node.collection, facet: entry.facet, epoch: node.epoch, baseSeq: node.baseSeq, deleted: node.deleted });
      expect(hex(aad)).toBe(v.facetAadHex[position]);
      const value = nodes.decryptFacet(unwrapped, node, entry.facet, primitives.decodeBase64Url(entry.ciphertext));
      expect(JSON.stringify(value)).toBe(v.facetPlaintextUtf8[position]);
    });
    expect(hex(nodes.nodeWriteMessage(node))).toBe(v.writeMessageHex);
    const signature = primitives.sign(fromHex(v.authorSignSecHex), nodes.nodeWriteMessage(node));
    expect(hex(signature)).toBe(v.writeSignatureHex);
  });

  test("blob canonical bytes", () => {
    const v = vectors.blob;
    const bytes = nodes.canonicalBlobBytes(v.descriptorJson);
    expect(new TextDecoder().decode(bytes)).toBe(v.canonicalBlobUtf8);
    expect(hex(primitives.hash(bytes))).toBe(v.canonicalBlobHashHex);
  });

  test("grants seal the node key or the facet keys to the principal", () => {
    const v = vectors.grant;
    const principalPub = fromHex(v.principalEncPubHex);
    const principalSec = fromHex(v.principalEncSecHex);
    const whole = primitives.sealOpen(principalPub, principalSec, fromHex(v.wholeNode.wrappedKeysHex));
    expect(hex(whole)).toBe(v.nodeKeyHex);
    expect(v.wholeNode.facetsCsv).toBe("");
    const facets = primitives.sealOpen(principalPub, principalSec, fromHex(v.facetGrant.wrappedKeysHex));
    expect(hex(facets)).toBe(v.facetGrant.sealedPlaintextHex);
    expect(v.facetGrant.facetsCsv).toBe("1");
  });

  test("access log entries are reproduced (contract amendment 1)", () => {
    const v = vectors.accessLog;
    for (const { entryJson, entryBytesHex, entryHashHex, signatureHex } of v.entries) {
      const entryBytes = nodes.accessEntryBytes({
        ...entryJson,
        prevHash: primitives.decodeBase64Url(entryJson.prevHash),
        wrappedKeysHash: primitives.decodeBase64Url(entryJson.wrappedKeysHash),
      });
      expect(hex(entryBytes)).toBe(entryBytesHex);
      expect(hex(primitives.hash(entryBytes))).toBe(entryHashHex);
      let signSec = v.ownerSignSecHex;
      if (entryJson.actorType === "install") {
        signSec = v.installSignSecHex;
      }
      expect(hex(primitives.sign(fromHex(signSec), entryBytes))).toBe(signatureHex);
    }
  });

  test("delegation signature covers the exact certificate bytes", () => {
    const v = vectors.delegation;
    const bytes = fromHex(v.certBytesHex);
    expect(hex(nodes.delegationMessage(bytes))).toBe(v.signatureMessageHex);
    expect(hex(primitives.sign(fromHex(v.userSignSecHex), nodes.delegationMessage(bytes)))).toBe(v.certSigHex);
  });
});
