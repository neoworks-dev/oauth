import { expect, type BrowserContext, type Page } from "@playwright/test";
import { createHash, randomBytes } from "node:crypto";

export interface TestAccount {
  email: string;
  password: string;
  recoveryWords: string[];
}

let counter = 0;

export function newAccount(): TestAccount {
  counter += 1;
  return { email: `e2e-${Date.now()}-${counter}@example.com`, password: "correct horse battery", recoveryWords: [] };
}

// collectViolations records CSP and Trusted Types errors the page logs.
export function collectViolations(page: Page): string[] {
  const violations: string[] = [];
  page.on("console", (message) => {
    const text = message.text();
    if (message.type() === "error" && /Content Security Policy|Trusted Type|Refused to/i.test(text)) {
      violations.push(text);
    }
  });
  page.on("pageerror", (error) => violations.push(String(error)));
  return violations;
}

// signUp walks the signup screens and leaves the browser on the account page.
export async function signUp(
  page: Page,
  account: TestAccount,
  options: { remember: boolean; escrow: boolean } = { remember: true, escrow: false },
) {
  await page.goto("/signup");
  await page.fill("#first-name", "Ada");
  await page.fill("#last-name", "Lovelace");
  await page.fill("#email", account.email);
  await page.fill("#password", account.password);
  await page.click("button[type=submit]");
  const hint = page.locator("#debug-code");
  await expect(hint).toContainText("Development code");
  const code = (await hint.textContent())!.replace(/\D/g, "");
  await page.fill("#code", code);
  await page.click("button[type=submit]");
  await expect(page.locator("#escrow-none")).toBeChecked();
  if (options.escrow) {
    await page.check("#escrow-help");
  }
  await page.click("#escrow-continue");
  await expect(page.locator("#recovery-words")).toBeVisible();
  account.recoveryWords = await page.locator("#recovery-words div").evaluateAll((items) =>
    items.map((item) => (item.textContent || "").replace(/^\d+\./, "").trim()));
  await page.check("#recovery-confirm");
  if (!options.remember) {
    await page.uncheck("#remember");
  }
  await page.click("#confirm-recovery");
  await expect(page.locator("h1")).toHaveText("Your account");
}

export async function signIn(page: Page, account: TestAccount, remember = true) {
  await page.fill("#email", account.email);
  await page.fill("#password", account.password);
  if (!remember) {
    await page.uncheck("#remember");
  }
  await page.click("button[type=submit]");
}

// latestMail reads the newest email sent to an address from the devstack mailbox.
export async function latestMail(page: Page, address: string): Promise<{ subject: string; text: string }> {
  const oauthOrigin = process.env.OAUTH_ORIGIN!;
  const response = await page.request.get(`${oauthOrigin}/__devstack/mail?to=${encodeURIComponent(address)}`);
  expect(response.status()).toBe(200);
  return response.json();
}

// verifyEmailForReset walks the forgot-password screens up to the method choice.
export async function verifyEmailForReset(page: Page, account: TestAccount) {
  await page.goto("/recover");
  await page.fill("#email", account.email);
  await page.click("button[type=submit]");
  const code = (await page.locator("#debug-code").textContent())!.replace(/\D/g, "");
  await page.fill("#code", code);
  await page.click("button[type=submit]");
}

// authenticatorToken signs the authenticator client in through the real OAuth
// flow, in a second page that shares the vault session, and returns its token.
export async function authenticatorToken(context: BrowserContext): Promise<string> {
  const oauthOrigin = process.env.OAUTH_ORIGIN!;
  const redirectUri = "http://localhost:19000/callback";
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest().toString("base64url");
  const query = new URLSearchParams({
    client_id: "neoworks-authenticator", redirect_uri: redirectUri, response_type: "code", scope: "openid",
    state: "s", code_challenge: challenge, code_challenge_method: "S256",
  });
  const helper = await context.newPage();
  await helper.route(`${redirectUri}**`, (route) => route.fulfill({ status: 200, contentType: "text/html", body: "ok" }));
  await helper.goto(`${oauthOrigin}/oauth/authorize?${query}`);
  await helper.waitForURL(`${redirectUri}**`);
  const code = new URL(helper.url()).searchParams.get("code")!;
  await helper.close();
  const response = await context.request.post(`${oauthOrigin}/oauth/token`, {
    form: { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: "neoworks-authenticator", code_verifier: verifier },
  });
  return (await response.json()).access_token;
}
