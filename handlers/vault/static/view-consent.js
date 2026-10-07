// Consent: the user chooses which parts of their account an app installation
// may read, and the vault wraps the matching keys to the install.

import { ApiError, describeError, isChallengeGone, getJson, postJson } from "./nw-api.js";
import { buildCertificate } from "./nw-nodes.js";
import { buildInstallGrants, buildKeyIndex, describeCollections, describeSharedNodes, heldRoles, planNewRoots } from "./nw-consent-tree.js";
import { errorBox, h, withBusy } from "./nw-dom.js";
import { requireUnlocked } from "./nw-keystore.js";
import { heading, mountView } from "./nw-layout.js";
import { collectionLabel, collectionOf, collectionRoles, describeScope, describeShare, isShareScope, shareCollections } from "./nw-scopes.js";
import { hash, utf8 } from "./nw-primitives.js";

const CERTIFICATE_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;

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

function approvedScopesFor(challenge, selections, shares) {
  return challenge.scopes.filter((scope) => {
    const collection = collectionOf(scope);
    if (collection === null) {
      return true;
    }
    if (isShareScope(scope)) {
      return shares[collection] === true && selections[collection] !== undefined;
    }
    return selections[collection] !== undefined;
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

const CONSENT_ATTEMPTS = 3;

// registryCollections is what the registry publishes for the requested collections.
function registryCollections(challenge) {
  if (!challenge.collections) {
    return {};
  }
  return challenge.collections;
}

function collectionLabels(collections, published) {
  const labels = {};
  for (const collection of collections) {
    labels[collection] = collectionLabel(collection, published);
  }
  return labels;
}

// approvedRoots are the planned new roots of the collections the user approved.
function approvedRoots(plan, selections) {
  return plan.newRoots.filter((root) => selections[root.node.collection] !== undefined);
}

function consentBody(context, plan) {
  const { challenge, identity, userId } = plan;
  const selections = nonEmptySelections(plan.selections);
  const scopes = approvedScopesFor(challenge, selections, plan.shares);
  const body = { loginChallenge: context.challengeId, scopes };
  if (!challenge.install || identity === null) {
    return body;
  }
  body.roots = approvedRoots(plan, selections);
  const certificate = buildCertificate({
    userId, clientId: challenge.clientId, install: challenge.install, scopes,
    signSec: identity.signSec, lifetimeMs: CERTIFICATE_LIFETIME_MS,
  });
  body.certificate = certificate.certificate;
  body.certificateSignature = certificate.certificateSignature;
  body.grants = buildInstallGrants({
    selections, collectionTrees: plan.collectionTrees, roles: collectionRoles(scopes), index: plan.index,
    held: plan.held, userId,
    heads: plan.heads, install: challenge.install, granter: { userId, signSec: identity.signSec },
    certId: certificate.certId,
  });
  return body;
}

// submitApproval posts the consent. When another writer extended an access log
// first, it re-reads the heads and signs the grants again.
async function submitApproval(context, plan) {
  for (let attempt = 1; attempt < CONSENT_ATTEMPTS; attempt += 1) {
    try {
      return await postConsent(context, plan);
    } catch (error) {
      if (!(error instanceof ApiError) || error.code !== "log_head_moved") {
        throw error;
      }
      plan.heads = { ...(await getJson("/vault/tree")).heads, ...plan.newRootHeads };
    }
  }
  return postConsent(context, plan);
}

async function postConsent(context, plan) {
  const result = await postJson("/vault/consent", consentBody(context, plan));
  window.location.assign(result.redirect);
}

async function loadPlan(context) {
  const challenge = context.challenge;
  const plan = {
    challenge, identity: null, userId: context.session.userId, collectionTrees: {}, sharedNodes: {},
    index: new Map(), held: new Map(), heads: {}, selections: {}, shares: {}, newRoots: [], newRootHeads: {},
  };
  const roles = collectionRoles(challenge.scopes);
  const requested = Object.keys(roles);
  if (challenge.install && requested.length > 0) {
    const unlocked = requireUnlocked();
    plan.identity = unlocked.identity;
    const tree = await getJson("/vault/tree");
    const labels = collectionLabels(requested, registryCollections(challenge));
    plan.index = buildKeyIndex(tree, unlocked.identity);
    plan.collectionTrees = describeCollections(tree, plan.index, plan.userId, requested, labels);
    plan.sharedNodes = describeSharedNodes(tree, plan.index, plan.userId);
    plan.held = heldRoles(tree, plan.index);
    addNewRoots(plan, planNewRoots({
      collections: requested, collectionTrees: plan.collectionTrees, userId: plan.userId, identity: unlocked.identity, labels,
    }));
    plan.heads = { ...tree.heads, ...plan.newRootHeads };
    plan.selections = wholeSelections(plan.collectionTrees, roles);
  }
  return plan;
}

// addNewRoots makes the roots this consent creates grantable like existing ones.
function addNewRoots(plan, planned) {
  plan.newRoots = planned.roots;
  plan.newRootHeads = planned.heads;
  for (const [nodeId, entry] of planned.keys) {
    plan.index.set(nodeId, entry);
  }
  Object.assign(plan.collectionTrees, planned.trees);
}

function scopeList(challenge) {
  const shown = challenge.scopes.filter((scope) => !isShareScope(scope));
  const published = registryCollections(challenge);
  return h("ul", { class: "scopes" }, shown.map((scope) => h("li", null, describeScope(scope, published))));
}

// shareChoices renders the optional permission to share a collection with other
// people. Each starts unchecked and is only granted when the user ticks it.
function shareChoices(plan) {
  return shareCollections(plan.challenge.scopes)
    .filter((collection) => plan.selections[collection] !== undefined)
    .map((collection) => {
      plan.shares[collection] = false;
      return nodeCheckbox("share-" + elementKey(collection), describeShare(collection, registryCollections(plan.challenge)), 0, false, false, (checked) => {
        plan.shares[collection] = checked;
      });
    });
}

// elementKey turns a collection path such as "@neoworks/calendar" into an
// element id part such as "neoworks-calendar".
function elementKey(collection) {
  return collection.replace(/[^a-z0-9]+/g, "-").replace(/^-+/, "");
}

function nodeCheckbox(id, label, depth, checked, disabled, onChange) {
  const input = h("input", { type: "checkbox", id, checked, disabled });
  input.addEventListener("change", () => onChange(input.checked));
  return h("div", { class: "checkbox-row tree-row tree-depth-" + Math.min(depth, 4) }, input, h("label", { for: id }, label));
}

function collectionPicker(collection, collectionTree, selection, sharedNodes) {
  const containerBoxes = [];
  const label = collectionTree.root.name;
  const wholeBox = nodeCheckbox("whole-" + elementKey(collection), "All " + label, 0, true, false, (checked) => {
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
  return h("fieldset", { class: "collection-picker" }, h("legend", null, "Give access to " + label), rows, sharedRows(selection, sharedNodes));
}

// sharedRows lists what other people shared with the user. Passing it on to the
// app is allowed up to the user's own role on it, and is off unless ticked.
function sharedRows(selection, sharedNodes) {
  if (sharedNodes.length === 0) {
    return [];
  }
  const rows = [h("p", { class: "hint" }, "Shared with you")];
  for (const node of sharedNodes) {
    const label = node.name + (node.depth === 0 ? " (from " + node.ownerEmail + ")" : "");
    rows.push(nodeCheckbox("shared-" + node.id, label, node.depth, false, false, (checked) => {
      if (checked) {
        selection.nodeIds.add(node.id);
      } else {
        selection.nodeIds.delete(node.id);
      }
    }));
  }
  return rows;
}

function sharedFor(plan, collection) {
  if (plan.sharedNodes[collection] === undefined) {
    return [];
  }
  return plan.sharedNodes[collection];
}

function pickers(plan) {
  return Object.entries(plan.selections).map(([collection, selection]) =>
    collectionPicker(collection, plan.collectionTrees[collection], selection, sharedFor(plan, collection)));
}

export async function renderConsent(context) {
  const challenge = context.challenge;
  const failure = errorBox();
  let plan;
  try {
    plan = await loadPlan(context);
  } catch (error) {
    showConsentFailure(context, error);
    return;
  }
  const choices = shareChoices(plan);
  if (challenge.autoGrant && choices.length === 0) {
    await submitApproval(context, plan);
    return;
  }
  const allow = h("button", { type: "button", id: "allow" }, "Allow");
  allow.addEventListener("click", () => withBusy(allow, "Allowing…", async () => {
    try {
      await submitApproval(context, plan);
    } catch (error) {
      if (isChallengeGone(error)) {
        showConsentFailure(context, error);
        return;
      }
      failure.show(describeError(error));
    }
  }));
  const deny = h("button", { type: "button", class: "secondary", id: "deny", onclick: () => denyRequest(context) }, "Deny");
  mountView(context,
    ...heading(challenge.clientName + " wants access", context.session.email),
    installDetails(challenge), scopeList(challenge), ...pickers(plan), ...choices, failure.element,
    h("div", { class: "actions" }, deny, allow));
}

function installDetails(challenge) {
  if (!challenge.install) {
    return null;
  }
  return h("p", { class: "hint" }, "App installation: " + challenge.install.name + " (key " + installFingerprint(challenge.install) + ")");
}

// showConsentFailure replaces the consent screen; an expired or used request
// gets no retry because only a new authorization from the app can succeed.
function showConsentFailure(context, error) {
  if (isChallengeGone(error)) {
    mountView(context, ...heading("Sign-in expired", describeError(error)));
    return;
  }
  mountView(context, ...heading("Something went wrong", describeError(error)));
}

async function denyRequest(context) {
  try {
    const result = await postJson("/vault/deny", { loginChallenge: context.challengeId });
    window.location.assign(result.redirect);
  } catch (error) {
    showConsentFailure(context, error);
  }
}

