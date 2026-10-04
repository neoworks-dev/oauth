import { expect, test, type Page } from "@playwright/test";
import { createHash, randomBytes } from "node:crypto";
import { collectViolations, newAccount, signIn, signUp } from "./helpers";

const oauthOrigin = process.env.OAUTH_ORIGIN!;
const redirectUri = "http://localhost:19000/callback";

function base64Url(bytes: Buffer): string {
  return bytes.toString("base64url");
}

function authorizeUrl(clientId: string, scope: string) {
  const verifier = base64Url(randomBytes(32));
  const challenge = base64Url(createHash("sha256").update(verifier).digest());
  const installId = crypto.randomUUID();
  const query = new URLSearchParams({
    client_id: clientId, redirect_uri: redirectUri, response_type: "code", scope, state: "xyz",
    code_challenge: challenge, code_challenge_method: "S256", install_id: installId,
    install_enc_pub: base64Url(randomBytes(32)), install_sign_pub: base64Url(randomBytes(32)), install_name: "Test calendar",
  });
  return { url: `${oauthOrigin}/oauth/authorize?${query}`, verifier, installId };
}

// callbackCode stubs the client's redirect target and returns the code it receives.
async function awaitCallback(page: Page): Promise<URL> {
  await page.route(`${redirectUri}**`, (route) => route.fulfill({ status: 200, contentType: "text/html", body: "ok" }));
  await page.waitForURL(`${redirectUri}**`);
  return new URL(page.url());
}

async function exchange(page: Page, code: string, verifier: string, clientId: string) {
  const response = await page.request.post(`${oauthOrigin}/oauth/token`, {
    form: { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: clientId, code_verifier: verifier },
  });
  return { status: response.status(), body: await response.json() };
}

test("consent with a narrowed selection yields a token bound to the install", async ({ page }) => {
  const violations = collectViolations(page);
  const account = newAccount();
  await signUp(page, account);

  const request = authorizeUrl("e2e-app", "openid calendar:read calendar:write");
  await page.goto(request.url);
  await expect(page.locator("h1")).toContainText("wants access");
  await expect(page.locator("#whole-calendar")).toBeChecked();
  await expect(page.locator(".scopes li")).toHaveCount(3);

  await page.click("#allow");
  const callback = await awaitCallback(page);
  expect(callback.searchParams.get("state")).toBe("xyz");

  const tokens = await exchange(page, callback.searchParams.get("code")!, request.verifier, "e2e-app");
  expect(tokens.status).toBe(200);
  expect(tokens.body.neoworks_grant.installId).toBe(request.installId);
  expect(tokens.body.neoworks_grant.grants).toHaveLength(1);
  expect(tokens.body.neoworks_grant.grants[0].role).toBe("write");
  expect(tokens.body.neoworks_grant.certificate.length).toBeGreaterThan(100);

  const introspection = await page.request.post(`${oauthOrigin}/oauth/introspect`, {
    form: { token: tokens.body.access_token }, headers: { Authorization: `Bearer ${tokens.body.access_token}` },
  });
  expect((await introspection.json()).install_id).toBe(request.installId);
  expect(violations).toEqual([]);
});

test("a first-party client is approved without a click", async ({ page }) => {
  const account = newAccount();
  await signUp(page, account);

  const request = authorizeUrl("e2e-first-party", "openid email contacts:read photos:read");
  await page.goto(request.url);
  const callback = await awaitCallback(page);
  const tokens = await exchange(page, callback.searchParams.get("code")!, request.verifier, "e2e-first-party");
  expect(tokens.status).toBe(200);
  expect(tokens.body.neoworks_grant.grants).toHaveLength(2);
});

test("login happens on the vault when the browser has no session", async ({ page }) => {
  const account = newAccount();
  await signUp(page, account);
  await page.click("#sign-out");

  const request = authorizeUrl("e2e-app", "openid files:read");
  await page.goto(request.url);
  await expect(page.locator("h1")).toHaveText("Sign in");
  await expect(page.locator(".subtitle")).toContainText("Test e2e-app");
  await signIn(page, account);
  await expect(page.locator("h1")).toContainText("wants access");
  await page.click("#deny");
  const callback = await awaitCallback(page);
  expect(callback.searchParams.get("error")).toBe("access_denied");
});

test("a request with a swapped redirect address never reaches the vault", async ({ page }) => {
  const request = authorizeUrl("e2e-app", "openid");
  const hostile = request.url.replace(encodeURIComponent(redirectUri), encodeURIComponent("http://evil.test/callback"));
  await page.goto(hostile);
  await expect(page).toHaveURL(/\/oauth\/error/);
  await expect(page.locator(".description")).toContainText("registered");
});
