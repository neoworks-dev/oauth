// Consent: the user chooses which parts of their account an app installation
// may read, and the vault wraps the matching keys to the install.

import { describeError, getJson, postJson } from "./nw-api.js";
import { buildCertificate } from "./nw-nodes.js";
import { buildInstallGrants, buildKeyIndex, describeCollections } from "./nw-consent-tree.js";
import { errorBox, h, withBusy } from "./nw-dom.js";
import { requireUnlocked } from "./nw-keystore.js";
import { heading, mountView } from "./nw-layout.js";
import { collectionLabel, collectionOf, collectionRoles, describeScope } from "./nw-scopes.js";
import { hash, utf8 } from "./nw-primitives.js";

const CERTIFICATE_LIFETIME_MS = 365 * 24 * 60 * 60 * 1000;

function installFingerprint(install) {
  const digest = hash(utf8(install.encPub + install.signPub));
  const hex = Array.from(digest.slice(0, 8), (byte) => byte.toString(16).padStart(2, "0")).join("");
  return hex.match(/.{4}/g).join(" ");
}

function wholeSelections(collectionTrees, roles) {
  const selections = {};
  for (const collection of Object.keys(roles)) {
    if (collectionTrees[collection]) {
      selections[collection] = { whole: true, nodeIds: new Set() };
    }
  }
  return selections;
}

function approvedScopesFor(challenge, selections) {
  return challenge.scopes.filter((scope) => {
    const collection = collectionOf(scope);
    return collection === null || selections[collection] !== undefined;
  });
}

function hasSelection(selection) {
  return selection.whole || selection.nodeIds.size > 0;
}

function nonEmptySelections(selections) {
  const kept = {};
  for (const [collection, selection] of Object.entries(selections)) {
    if (hasSelection(selection)) {
      kept[collection] = selection;
    }
  }
  return kept;
}

async function submitApproval(context, plan) {
  const { challenge, identity, userId } = plan;
  const selections = nonEmptySelections(plan.selections);
  const scopes = approvedScopesFor(challenge, selections);
  const body = { loginChallenge: context.challengeId, scopes };
  if (challenge.install) {
    const certificate = buildCertificate({
      userId, clientId: challenge.clientId, install: challenge.install, scopes,
      signSec: identity.signSec, lifetimeMs: CERTIFICATE_LIFETIME_MS,
    });
    body.certificate = certificate.certificate;
    body.certificateSignature = certificate.certificateSignature;
    body.grants = buildInstallGrants({
      selections, collectionTrees: plan.collectionTrees, roles: collectionRoles(scopes), index: plan.index,
      install: challenge.install, granter: { userId, signSec: identity.signSec }, certId: certificate.certId,
    });
  }
  const result = await postJson("/vault/consent", body);
  window.location.assign(result.redirect);
}

async function loadPlan(context) {
  const challenge = context.challenge;
  const unlocked = requireUnlocked();
  const plan = { challenge, identity: unlocked.identity, userId: unlocked.userId, collectionTrees: {}, index: new Map(), selections: {} };
  if (challenge.install && Object.keys(collectionRoles(challenge.scopes)).length > 0) {
    const tree = await getJson("/vault/tree");
    plan.index = buildKeyIndex(tree, unlocked.identity);
    plan.collectionTrees = describeCollections(tree, plan.index);
    plan.selections = wholeSelections(plan.collectionTrees, collectionRoles(challenge.scopes));
  }
  return plan;
}

function scopeList(challenge) {
  return h("ul", { class: "scopes" }, challenge.scopes.map((scope) => h("li", null, describeScope(scope))));
}

function nodeCheckbox(id, label, depth, checked, disabled, onChange) {
  const input = h("input", { type: "checkbox", id, checked, disabled });
  input.addEventListener("change", () => onChange(input.checked));
  return h("div", { class: "checkbox-row tree-row tree-depth-" + Math.min(depth, 4) }, input, h("label", { for: id }, label));
}

function collectionPicker(collection, collectionTree, selection) {
  const containerBoxes = [];
  const wholeBox = nodeCheckbox("whole-" + collection, "All " + collectionLabel(collection), 0, true, false, (checked) => {
    selection.whole = checked;
    for (const box of containerBoxes) {
      box.querySelector("input").disabled = checked;
    }
  });
  const rows = [wholeBox];
  for (const container of collectionTree.containers) {
    const row = nodeCheckbox("node-" + container.id, container.name, container.depth, false, true, (checked) => {
      if (checked) {
        selection.nodeIds.add(container.id);
      } else {
        selection.nodeIds.delete(container.id);
      }
    });
    containerBoxes.push(row);
    rows.push(row);
  }
  return h("fieldset", { class: "collection-picker" }, h("legend", null, "Share " + collectionLabel(collection)), rows);
}

function pickers(plan) {
  return Object.entries(plan.selections).map(([collection, selection]) =>
    collectionPicker(collection, plan.collectionTrees[collection], selection));
}

export async function renderConsent(context) {
  const challenge = context.challenge;
  const failure = errorBox();
  let plan;
  try {
    plan = await loadPlan(context);
  } catch (error) {
    mountView(context, ...heading("Something went wrong", describeError(error)));
    return;
  }
  if (challenge.autoGrant) {
    await submitApproval(context, plan);
    return;
  }
  const allow = h("button", { type: "button", id: "allow" }, "Allow");
  allow.addEventListener("click", () => withBusy(allow, "Allowing…", async () => {
    try {
      await submitApproval(context, plan);
    } catch (error) {
      failure.show(describeError(error));
    }
  }));
  const deny = h("button", { type: "button", class: "secondary", id: "deny", onclick: () => denyRequest(context) }, "Deny");
  mountView(context,
    ...heading(challenge.clientName + " wants access", context.session.email),
    installDetails(challenge), scopeList(challenge), ...pickers(plan), failure.element,
    h("div", { class: "actions" }, deny, allow));
}

function installDetails(challenge) {
  if (!challenge.install) {
    return null;
  }
  return h("p", { class: "hint" }, "App installation: " + challenge.install.name + " (key " + installFingerprint(challenge.install) + ")");
}

async function denyRequest(context) {
  const result = await postJson("/vault/deny", { loginChallenge: context.challengeId });
  window.location.assign(result.redirect);
}

