// What the consent screen decides from an app's earlier authorization. Pure
// functions: no DOM and no network.

import { collectionOf } from "./nw-scopes.js";

// canSkipConsent is true only for first-party apps that ask for no share
// choice. Third-party apps always show the screen, also when the user granted
// the same scopes before.
export function canSkipConsent(challenge, shareChoiceCount) {
  return challenge.firstParty === true && shareChoiceCount === 0;
}

function actionOf(scope) {
  return scope.slice(scope.lastIndexOf(":") + 1);
}

function holdsCollection(heldScopes, collection) {
  return heldScopes.some((held) => collectionOf(held) === collection);
}

// holdsAccess is true when the held scopes already give what the scope asks:
// the scope itself, or write for a read.
function holdsAccess(heldScopes, scope) {
  if (heldScopes.includes(scope)) {
    return true;
  }
  const collection = collectionOf(scope);
  return collection !== null && actionOf(scope) === "read" && heldScopes.includes(collection + ":write");
}

// requestStatus is "held" for access the app already has, "widened" for more
// access (write over read, a new share permission) in a collection it holds,
// and "new" for anything else.
export function requestStatus(scope, heldScopes) {
  if (holdsAccess(heldScopes, scope)) {
    return "held";
  }
  const collection = collectionOf(scope);
  if (collection !== null && holdsCollection(heldScopes, collection)) {
    return "widened";
  }
  return "new";
}

// classifyRequest splits the requested scopes by status. Without an earlier
// authorization everything is new.
export function classifyRequest(requestedScopes, history) {
  const heldScopes = heldScopesOf(history);
  const classified = { held: [], widened: [], added: [] };
  for (const scope of requestedScopes) {
    const status = requestStatus(scope, heldScopes);
    if (status === "held") {
      classified.held.push(scope);
    } else if (status === "widened") {
      classified.widened.push(scope);
    } else {
      classified.added.push(scope);
    }
  }
  return classified;
}

export function heldScopesOf(history) {
  if (history === null || history === undefined) {
    return [];
  }
  return history.scopes;
}

function isRequested(scope, requestedScopes) {
  if (requestedScopes.includes(scope)) {
    return true;
  }
  const collection = collectionOf(scope);
  return collection !== null && actionOf(scope) === "read" && requestedScopes.includes(collection + ":write");
}

// keptScopes are the collection scopes the app holds and no longer asks for.
export function keptScopes(requestedScopes, history) {
  return heldScopesOf(history).filter((scope) => collectionOf(scope) !== null && !isRequested(scope, requestedScopes));
}

// keptCollections are the held collections the request does not mention at
// all, the ones whose access can be revoked from the consent screen.
export function keptCollections(requestedScopes, history) {
  const requested = requestedScopes.map(collectionOf);
  const kept = [];
  for (const scope of keptScopes(requestedScopes, history)) {
    const collection = collectionOf(scope);
    if (!requested.includes(collection) && !kept.includes(collection)) {
      kept.push(collection);
    }
  }
  return kept;
}

// accessByCollection lists the nodes the app's installs can reach per
// collection, once each, with the highest role any install holds.
export function accessByCollection(history) {
  const byCollection = {};
  if (history === null || history === undefined) {
    return byCollection;
  }
  for (const held of history.access) {
    if (byCollection[held.collection] === undefined) {
      byCollection[held.collection] = [];
    }
    const nodes = byCollection[held.collection];
    const known = nodes.find((node) => node.nodeId === held.nodeId);
    if (known === undefined) {
      nodes.push({ nodeId: held.nodeId, role: held.role });
    } else if (held.role === "write") {
      known.role = "write";
    }
  }
  return byCollection;
}
