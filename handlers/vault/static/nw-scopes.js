// Scope helpers for the consent screen.

import { ROOT_COLLECTIONS } from "./nw-nodes.js";

const COLLECTION_LABELS = {
  calendar: "calendars", contacts: "contacts", photos: "photos", files: "files", google: "linked Google account",
};

const IDENTITY_TEXT = {
  openid: "Know who you are",
  profile: "See your name",
  email: "See your email address",
};

export function collectionOf(scope) {
  const [collection] = scope.split(":");
  if (scope.includes(":") && ROOT_COLLECTIONS.includes(collection)) {
    return collection;
  }
  return null;
}

export function isShareScope(scope) {
  return scope.endsWith(":share") && collectionOf(scope) !== null;
}

// shareCollections lists the collections an app asks to share with other people.
export function shareCollections(scopes) {
  return scopes.filter(isShareScope).map(collectionOf);
}

export function describeShare(collection) {
  return "Share your " + COLLECTION_LABELS[collection] + " with other people";
}

// collectionRoles maps each requested collection to the highest role requested.
export function collectionRoles(scopes) {
  const roles = {};
  for (const scope of scopes) {
    const collection = collectionOf(scope);
    if (collection === null || isShareScope(scope)) {
      continue;
    }
    if (scope.endsWith(":write") || roles[collection] === undefined) {
      roles[collection] = scope.split(":")[1];
    }
  }
  return roles;
}

export function describeScope(scope) {
  const collection = collectionOf(scope);
  if (collection === null) {
    return IDENTITY_TEXT[scope];
  }
  if (isShareScope(scope)) {
    return describeShare(collection);
  }
  if (collection === "google") {
    return "Access your linked Google account";
  }
  if (scope.endsWith(":write")) {
    return "View and change your " + COLLECTION_LABELS[collection];
  }
  return "View your " + COLLECTION_LABELS[collection];
}

export function collectionLabel(collection) {
  return COLLECTION_LABELS[collection];
}
