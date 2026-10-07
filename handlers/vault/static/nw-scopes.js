// Scope helpers for the consent screen. A collection is the registry path
// `@scope/name` of a published schema; `collections` maps each to its registry
// entry ({ title, descriptor }).

const COLLECTION_PATTERN = /^@[a-z0-9][a-z0-9._-]{0,63}\/[a-z0-9][a-z0-9._-]{0,63}$/;
const COLLECTION_ACTIONS = ["read", "write", "share"];

const IDENTITY_TEXT = {
  openid: "Know who you are",
  profile: "See your name",
  email: "See your email address",
};

function splitScope(scope) {
  const separator = scope.lastIndexOf(":");
  if (separator < 0) {
    return null;
  }
  const collection = scope.slice(0, separator);
  const action = scope.slice(separator + 1);
  if (!COLLECTION_PATTERN.test(collection) || !COLLECTION_ACTIONS.includes(action)) {
    return null;
  }
  return { collection, action };
}

export function collectionOf(scope) {
  const parts = splitScope(scope);
  if (parts === null) {
    return null;
  }
  return parts.collection;
}

export function isShareScope(scope) {
  const parts = splitScope(scope);
  return parts !== null && parts.action === "share";
}

// shareCollections lists the collections an app asks to share with other people.
export function shareCollections(scopes) {
  return scopes.filter(isShareScope).map(collectionOf);
}

// collectionLabel is the collection's registry title, or its path when the
// registry has none.
export function collectionLabel(collection, collections) {
  const entry = collections[collection];
  if (entry && entry.title) {
    return entry.title;
  }
  return collection;
}

export function describeShare(collection, collections) {
  return "Share your " + collectionLabel(collection, collections) + " with other people";
}

// collectionRoles maps each requested collection to the highest role requested.
export function collectionRoles(scopes) {
  const roles = {};
  for (const scope of scopes) {
    const parts = splitScope(scope);
    if (parts === null || parts.action === "share") {
      continue;
    }
    if (parts.action === "write" || roles[parts.collection] === undefined) {
      roles[parts.collection] = parts.action;
    }
  }
  return roles;
}

export function describeScope(scope, collections) {
  const parts = splitScope(scope);
  if (parts === null) {
    return IDENTITY_TEXT[scope];
  }
  if (parts.action === "share") {
    return describeShare(parts.collection, collections);
  }
  const label = collectionLabel(parts.collection, collections);
  if (parts.action === "write") {
    return "View and change your " + label;
  }
  return "View your " + label;
}
