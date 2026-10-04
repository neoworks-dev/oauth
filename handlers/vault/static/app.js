// Entry point of the account vault single-page app. It keeps the plaintext AMK
// alive across views by navigating with the History API instead of reloading.

import { ensureAccess, ensureSession } from "./flows.js";
import { ApiError, getJson } from "./nw-api.js";
import { h } from "./nw-dom.js";
import { noteActivity, setLockListener } from "./nw-keystore.js";
import { heading, mountView } from "./nw-layout.js";
import { collectionRoles } from "./nw-scopes.js";
import { ready } from "./nw-primitives.js";
import { renderAccount } from "./view-account.js";
import { renderCancelRecovery } from "./view-cancel-recovery.js";
import { renderConsent } from "./view-consent.js";
import { renderRecover } from "./view-recover.js";
import { renderSignup } from "./view-signup.js";

const root = document.getElementById("app");
const context = {
  root,
  view: h("div", { id: "view" }),
  boot: JSON.parse(root.dataset.boot),
  session: null,
  challenge: null,
  challengeId: "",
  challengeQuery: "",
  lockedByIdle: false,
  cancelOnNavigate: null,
  navigate,
};

function navigate(path) {
  history.pushState({}, "", path);
  route();
}

function readChallengeId() {
  const challengeId = new URLSearchParams(location.search).get("login_challenge");
  if (challengeId === null) {
    return "";
  }
  return challengeId;
}

function showFatal(message) {
  mountView(context, ...heading("Something went wrong", message));
}

// loadChallenge fetches the pending authorization request named in the URL.
// It returns false after showing an error when the request is gone.
async function loadChallenge() {
  context.challengeId = readChallengeId();
  context.challengeQuery = "";
  context.challenge = null;
  if (context.challengeId === "") {
    return true;
  }
  context.challengeQuery = "?login_challenge=" + encodeURIComponent(context.challengeId);
  try {
    context.challenge = await getJson("/vault/challenge" + context.challengeQuery);
    return true;
  } catch (error) {
    showFatal("This sign-in request has expired. Go back to the app and start again.");
    return false;
  }
}

function continueAfterAccess() {
  if (context.challenge) {
    renderConsent(context);
    return;
  }
  navigate("/account");
}

// needsKeys is true when approving the request wraps keys to an install.
function needsKeys(challenge) {
  if (challenge === null || challenge.install === null) {
    return false;
  }
  return Object.keys(collectionRoles(challenge.scopes)).length > 0;
}

async function routeSignin() {
  if (!(await loadChallenge())) {
    return;
  }
  if (needsKeys(context.challenge) || context.challenge === null) {
    await ensureAccess(context, continueAfterAccess);
    return;
  }
  await ensureSession(context, continueAfterAccess);
}

async function routeSignup() {
  if (await loadChallenge()) {
    renderSignup(context, { onDone: () => navigate("/signin" + context.challengeQuery) });
  }
}

async function routeAccount() {
  await ensureAccess(context, (session) => renderAccount(context, session));
}

function routeHandoverLanding() {
  mountView(context, ...heading("Open the Neoworks Authenticator",
    "This link is opened by the Neoworks Authenticator app on your phone. If nothing happened, install the app and scan the code on the sign-in screen."));
}

const ROUTES = {
  "/": routeAccount,
  "/account": routeAccount,
  "/signin": routeSignin,
  "/signup": routeSignup,
  "/recover": () => renderRecover(context),
  "/recover/cancel": () => renderCancelRecovery(context),
  "/handover": routeHandoverLanding,
};

async function route() {
  if (context.cancelOnNavigate) {
    context.cancelOnNavigate();
    context.cancelOnNavigate = null;
  }
  const handler = ROUTES[location.pathname];
  if (handler === undefined) {
    showFatal("This page does not exist.");
    return;
  }
  try {
    await handler();
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      await ensureAccess(context, continueAfterAccess);
      return;
    }
    showFatal("The page could not be loaded.");
  }
}

function start() {
  root.append(context.view);
  window.addEventListener("popstate", route);
  for (const eventName of ["pointerdown", "keydown"]) {
    window.addEventListener(eventName, noteActivity);
  }
  setLockListener(() => {
    context.lockedByIdle = true;
    route();
  });
  route();
}

ready().then(start);
