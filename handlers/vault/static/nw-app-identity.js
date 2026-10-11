// How the consent screen introduces an app: its initials and colour when it has
// no logo, who is behind it, and whether its domains are verified. Pure
// functions: no DOM and no network.

const LOGO_HUE_SPAN = 360;

// initialsOf is up to two capital letters from the first words of the name.
export function initialsOf(name) {
  const words = name.split(/[^\p{L}\p{N}]+/u).filter((word) => word !== "");
  if (words.length === 0) {
    return "?";
  }
  const letters = words.slice(0, 2).map((word) => Array.from(word)[0]);
  return letters.join("").toUpperCase();
}

// colourFor derives a stable colour from the client id, so an app without a
// logo always shows the same badge.
export function colourFor(clientId) {
  let hash = 5381;
  for (const character of clientId) {
    hash = (hash * 33 + character.codePointAt(0)) % 2147483647;
  }
  return "hsl(" + (hash % LOGO_HUE_SPAN) + " 55% 38%)";
}

// ownerText names an owner the way the screen shows it.
export function ownerText(owner) {
  let text = owner.displayName + " (@" + owner.handle + ")";
  if (owner.verified) {
    text += ", verified organization";
  }
  return text;
}

// collectionOwner is the owner of the scope a collection `@scope/name` lives in,
// or null when nobody holds the scope.
export function collectionOwner(collection, scopeOwners) {
  if (!scopeOwners) {
    return null;
  }
  const handle = collection.slice(1).split("/")[0];
  const owner = scopeOwners[handle];
  if (owner === undefined) {
    return null;
  }
  return owner;
}

// ownerLine says who published the app.
export function ownerLine(challenge) {
  if (challenge.owner === null || challenge.owner === undefined) {
    return "Publisher unknown.";
  }
  return "Published by " + ownerText(challenge.owner) + ".";
}

// verificationNotice is the text and state of the badge under the app's name:
// "first-party" for Neoworks' own apps, "verified" when the owner proved the
// domains of the app, "unverified" otherwise.
export function verificationNotice(challenge) {
  if (challenge.firstParty === true) {
    return { state: "first-party", text: "Made by Neoworks." };
  }
  if (challenge.verified === true && challenge.owner) {
    return {
      state: "verified",
      text: "Third-party app, verified by " + challenge.owner.displayName + " (@" + challenge.owner.handle +
        "): its sign-in and home page addresses are on domains they control.",
    };
  }
  return { state: "unverified", text: "Third-party app: not made by Neoworks and not verified." };
}

// reviewNotice is shown for apps Neoworks reviewed; null otherwise.
export function reviewNotice(challenge) {
  if (challenge.firstParty !== true && challenge.reviewStatus === "approved") {
    return "Reviewed and approved by Neoworks.";
  }
  return null;
}
