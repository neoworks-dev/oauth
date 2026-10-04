// Browser side of the authenticator handover (contract section 9). The vault
// shows a QR code holding an ephemeral public key; the authenticator seals the
// AMK to it after biometrics and the vault polls for the result.

import { pollJson, postJson } from "./nw-api.js";
import { h } from "./nw-dom.js";
import {
  boxKeypair, decodeBase64Url, encodeBase64Url, sealOpen, utf8, wipe,
} from "./nw-primitives.js";

const POLL_INTERVAL_MS = 2000;
const HANDOVER_SECONDS = 120;

export function handoverPayload({ sessionId, tempPub, vaultOrigin }) {
  const document = JSON.stringify({ v: 1, sessionId, tempPub: encodeBase64Url(tempPub), vaultOrigin });
  return "nwh1:" + encodeBase64Url(utf8(document));
}

// handoverAppLink is used when the authenticator is on the same phone.
export function handoverAppLink(vaultOrigin, payload) {
  return vaultOrigin + "/handover#p=" + payload;
}

async function waitForDelivery(sessionId, signal) {
  const deadline = Date.now() + HANDOVER_SECONDS * 1000;
  while (Date.now() < deadline && !signal.cancelled) {
    const reply = await pollJson("/vault/handover/" + sessionId);
    if (reply.status === 200) {
      return reply.body;
    }
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }
  return null;
}

// startHandover registers a handover session, renders the QR into the
// container and resolves with the AMK once the authenticator delivers it. It
// resolves with null on timeout or cancellation. The caller checks the AMK
// against the account before trusting it.
export async function startHandover({ container, vaultOrigin, expectedUserId, signal }) {
  const tempKeys = boxKeypair();
  const sessionId = crypto.randomUUID();
  await postJson("/vault/handover", { sessionId });
  const payload = handoverPayload({ sessionId, tempPub: tempKeys.publicKey, vaultOrigin });
  container.replaceChildren(
    h("img", { class: "handover-qr", alt: "Scan with the Neoworks Authenticator", width: 240, height: 240, src: "/vault/qr.png?p=" + encodeURIComponent(payload) }),
    h("a", { class: "hint", href: handoverAppLink(vaultOrigin, payload) }, "Authenticator on this device? Open it here."));
  const delivery = await waitForDelivery(sessionId, signal);
  if (delivery === null || delivery.userId !== expectedUserId) {
    wipe(tempKeys.secretKey);
    return null;
  }
  const amk = sealOpen(tempKeys.publicKey, tempKeys.secretKey, decodeBase64Url(delivery.sealed));
  wipe(tempKeys.secretKey);
  return amk;
}

