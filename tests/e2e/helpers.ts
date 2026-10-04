import { expect, type Page } from "@playwright/test";

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
export async function signUp(page: Page, account: TestAccount, options: { remember: boolean } = { remember: true }) {
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
