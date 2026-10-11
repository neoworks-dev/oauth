// The parts of the consent screen that depend on the app's earlier
// authorization: whether it is first-party, what the user used it for before,
// what it already holds, what is new and what it keeps.

import { describeError, getJson, postJson } from "./nw-api.js";
import { colourFor, collectionOwner, initialsOf, ownerLine, ownerText, reviewNotice, verificationNotice } from "./nw-app-identity.js";
import { accessByCollection, classifyRequest, heldScopesOf, keptCollections, keptScopes } from "./nw-consent-history.js";
import { buildKeyIndex, nodeNames } from "./nw-consent-tree.js";
import { errorBox, h, withBusy } from "./nw-dom.js";
import { isUnlocked, requireUnlocked } from "./nw-keystore.js";
import { collectionLabel, collectionOf, describeScope, isShareScope } from "./nw-scopes.js";

const ROLE_TEXT = { read: "view", write: "view and change" };

function formatTime(value) {
  return new Date(value).toLocaleString();
}

// appIdentity introduces the app: its logo (or initials on a colour derived from
// its id), its name, who published it and whether its domains are verified. A
// third-party app is always marked, and marked unverified until its owner proved
// the domains it uses.
export function appIdentity(challenge) {
  const notice = verificationNotice(challenge);
  const review = reviewNotice(challenge);
  const lines = [
    h("p", { class: "app-name", id: "app-name" }, challenge.clientName),
    h("p", { class: "hint", id: "app-owner" }, ownerLine(challenge)),
  ];
  if (challenge.description) {
    lines.push(h("p", { class: "hint", id: "app-description" }, challenge.description));
  }
  const identity = [h("div", { class: "app-identity" }, appLogo(challenge), h("div", { class: "app-identity-text" }, lines))];
  if (challenge.firstParty !== true) {
    identity.push(h("p", { class: "app-badge", id: "third-party-notice", "data-verification": notice.state }, notice.text));
  }
  if (review !== null) {
    identity.push(h("p", { class: "hint", id: "app-review" }, review));
  }
  return identity;
}

// appLogo is the logo image, or the initials badge when the app has no logo a
// user may see.
function appLogo(challenge) {
  if (challenge.logoUrl) {
    return h("img", { class: "app-logo", id: "app-logo", src: challenge.logoUrl, alt: "" });
  }
  const badge = h("span", { class: "app-logo app-logo-initials", id: "app-logo" }, initialsOf(challenge.clientName));
  badge.style.backgroundColor = colourFor(challenge.clientId);
  return badge;
}

// ownerNote names who owns the scope a collection lives in.
export function ownerNote(challenge, collection) {
  const owner = collectionOwner(collection, challenge.scopeOwners);
  if (owner === null) {
    return null;
  }
  return h("span", { class: "scope-owner" }, "from " + ownerText(owner));
}

// loadHeldNames names the nodes the app's installs reach. It returns an empty
// map while the account is locked, which leaves the collection titles.
export async function loadHeldNames(history) {
  if (history === null || history.access.length === 0 || !isUnlocked()) {
    return new Map();
  }
  try {
    const tree = await getJson("/vault/tree");
    const index = buildKeyIndex(tree, requireUnlocked().identity);
    return nodeNames(tree, index, history.access.map((held) => held.nodeId));
  } catch (error) {
    return new Map();
  }
}

function installLabel(install, currentInstall) {
  let label = install.name;
  if (currentInstall !== null && currentInstall.id === install.id) {
    label += " (this device)";
  }
  if (install.revokedAt !== null) {
    label += " (revoked)";
  }
  return label;
}

function returningSummary(challenge) {
  const history = challenge.history;
  const labels = history.installs.map((install) => installLabel(install, challenge.install));
  const summary = [
    h("p", { id: "returning-app" }, "You have used " + challenge.clientName + " before."),
    h("p", { class: "hint", id: "authorization-times" },
      "First authorized " + formatTime(history.firstAuthorizedAt) + ", most recently " + formatTime(history.lastAuthorizedAt) + "."),
  ];
  if (labels.length > 0) {
    summary.push(h("p", { class: "hint", id: "install-names" }, "Installations: " + labels.join(", ")));
  }
  return summary;
}

function nodeLine(node, names, label) {
  const name = names.get(node.nodeId);
  if (name === undefined) {
    return h("li", null, label + " (" + ROLE_TEXT[node.role] + ")");
  }
  return h("li", null, name + " (" + ROLE_TEXT[node.role] + ")");
}

// accessItem is a collection the app holds with the nodes it reaches in it.
function accessItem(challenge, collection, names) {
  const label = collectionLabel(collection, challenge.collections);
  const nodes = accessByCollection(challenge.history)[collection];
  const lines = [];
  if (nodes !== undefined) {
    lines.push(h("ul", { class: "access-nodes" }, nodes.map((node) => nodeLine(node, names, label))));
  }
  return h("li", { "data-collection": collection }, h("strong", null, label), " ", ownerNote(challenge, collection), lines);
}

function heldCollections(challenge) {
  const requested = challenge.scopes.map(collectionOf);
  const held = [];
  for (const scope of heldScopesOf(challenge.history)) {
    const collection = collectionOf(scope);
    if (collection !== null && requested.includes(collection) && !held.includes(collection)) {
      held.push(collection);
    }
  }
  return held;
}

function alreadyGranted(challenge, names) {
  const collections = heldCollections(challenge);
  if (collections.length === 0) {
    return [];
  }
  return [
    h("h2", null, "Already granted"),
    h("ul", { class: "scopes", id: "granted-access" }, collections.map((collection) => accessItem(challenge, collection, names))),
  ];
}

// scopeOwnerNote names the owner of the collection a scope is for; identity
// scopes have none.
export function scopeOwnerNote(challenge, scope) {
  const collection = collectionOf(scope);
  if (collection === null) {
    return null;
  }
  return ownerNote(challenge, collection);
}

function scopeItem(challenge, scope, tag) {
  const text = describeScope(scope, challenge.collections);
  return h("li", { class: "scope-" + tag.kind }, text, " ", scopeOwnerNote(challenge, scope), h("span", { class: "scope-tag" }, tag.text));
}

// newlyRequested lists the non-share scopes that are new or widen access; the
// share permissions carry their tag in their own checkbox.
function newlyRequested(challenge) {
  const classified = classifyRequest(challenge.scopes, challenge.history);
  const added = classified.added.filter((scope) => !isShareScope(scope));
  const widened = classified.widened.filter((scope) => !isShareScope(scope));
  const items = [
    ...added.map((scope) => scopeItem(challenge, scope, { kind: "new", text: "New" })),
    ...widened.map((scope) => scopeItem(challenge, scope, { kind: "widened", text: "More access than before" })),
  ];
  if (items.length === 0) {
    return [h("h2", null, "Newly requested"), h("p", { class: "hint", id: "nothing-new" }, "Nothing new: " + challenge.clientName + " asks for access it already has.")];
  }
  return [h("h2", null, "Newly requested"), h("ul", { class: "scopes", id: "requested-access" }, items)];
}

function revokeButton(context, collection, row, failure) {
  const button = h("button", { type: "button", class: "secondary", "data-revoke": collection }, "Revoke");
  button.addEventListener("click", () => withBusy(button, "Revoking…", async () => {
    try {
      await postJson("/vault/consent/revoke", { loginChallenge: context.challengeId, collection });
      row.remove();
    } catch (error) {
      failure.show(describeError(error));
    }
  }));
  return button;
}

function keptItems(context, names, failure) {
  const challenge = context.challenge;
  const revocable = keptCollections(challenge.scopes, challenge.history);
  const collections = [];
  for (const scope of keptScopes(challenge.scopes, challenge.history)) {
    const collection = collectionOf(scope);
    if (!collections.includes(collection)) {
      collections.push(collection);
    }
  }
  return collections.map((collection) => {
    const item = accessItem(challenge, collection, names);
    if (revocable.includes(collection)) {
      item.append(revokeButton(context, collection, item, failure));
    }
    return item;
  });
}

function keptAccess(context, names) {
  const failure = errorBox();
  const items = keptItems(context, names, failure);
  if (items.length === 0) {
    return [];
  }
  return [
    h("h2", null, "Kept access"),
    h("p", { class: "hint" }, context.challenge.clientName + " still has this access but does not ask for it now."),
    h("ul", { class: "scopes", id: "kept-access" }, items),
    failure.element,
  ];
}

// historySections is everything above the picker for an app the user
// authorized before; an app the user never authorized has none.
export function historySections(context, names) {
  const challenge = context.challenge;
  if (challenge.history === null) {
    return [];
  }
  return [
    ...returningSummary(challenge),
    ...alreadyGranted(challenge, names),
    ...newlyRequested(challenge),
    ...keptAccess(context, names),
  ];
}

// shareTag marks a share permission the app did not hold before.
export function shareTag(challenge, scope) {
  const classified = classifyRequest([scope], challenge.history);
  if (challenge.history === null || classified.held.length > 0) {
    return "";
  }
  return " (new permission)";
}
