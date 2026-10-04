import { expect, test } from "@playwright/test";
import { collectViolations, newAccount, signIn, signUp } from "./helpers";

test("signup, sign-out, sign-in and a remembered browser", async ({ page }) => {
  const violations = collectViolations(page);
  const account = newAccount();

  await signUp(page, account);
  await expect(page.locator("h1")).toHaveText("Your account");
  expect(account.recoveryWords).toHaveLength(24);

  await page.click("#sign-out");
  await expect(page.locator("h1")).toHaveText("Sign in");
  await page.goto("/account");
  await signIn(page, account);
  await expect(page.locator("h1")).toHaveText("Your account");

  // The device wrap unlocks this browser without the password.
  await page.reload();
  await expect(page.locator("h1")).toHaveText("Your account");
  await expect(page.locator("#browser-status")).toContainText("without a password");

  expect(violations).toEqual([]);
});

test("a wrong password is rejected and an unremembered browser asks again", async ({ page }) => {
  const violations = collectViolations(page);
  const account = newAccount();
  await signUp(page, account, { remember: false, escrow: false });
  await expect(page.locator("h1")).toHaveText("Your account");

  await page.reload();
  await expect(page.locator("h1")).toHaveText("Unlock your account");
  await page.fill("#password", "not the password");
  await page.click("button[type=submit]");
  await expect(page.locator(".error")).toBeVisible();
  await page.fill("#password", account.password);
  await page.click("button[type=submit]");
  await expect(page.locator("h1")).toHaveText("Your account");
  expect(violations).toEqual([]);
});

test("the server never receives the password", async ({ page }) => {
  const account = newAccount();
  const bodies: string[] = [];
  page.on("request", (request) => {
    const body = request.postData();
    if (body !== null) {
      bodies.push(body);
    }
  });
  await signUp(page, account);
  await page.click("#sign-out");
  await page.goto("/signin");
  await signIn(page, account);
  await expect(page.locator("h1")).toHaveText("Your account");
  expect(bodies.length).toBeGreaterThan(3);
  for (const body of bodies) {
    expect(body).not.toContain(account.password);
  }
});

test("change password", async ({ page }) => {
  const violations = collectViolations(page);
  const account = newAccount();
  await signUp(page, account);
  await page.fill("#current-password", account.password);
  await page.fill("#new-password", "a brand new passphrase");
  await page.click("text=Change password");
  await expect(page.locator("#password-changed")).toBeVisible();

  await page.click("#sign-out");
  await page.goto("/signin");
  await page.fill("#email", account.email);
  await page.fill("#password", account.password);
  await page.click("button[type=submit]");
  await expect(page.locator(".error")).toBeVisible();
  await page.fill("#password", "a brand new passphrase");
  await page.click("button[type=submit]");
  await expect(page.locator("h1")).toHaveText("Your account");
  expect(violations).toEqual([]);
});

test("forgot password with the recovery key", async ({ page }) => {
  const violations = collectViolations(page);
  const account = newAccount();
  await signUp(page, account, { remember: false, escrow: false });
  await page.click("#sign-out");

  await page.goto("/recover");
  await page.fill("#email", account.email);
  await page.click("button[type=submit]");
  const code = (await page.locator("#debug-code").textContent())!.replace(/\D/g, "");
  await page.fill("#code", code);
  await page.click("button[type=submit]");
  await page.fill("#recovery-words-input", account.recoveryWords.join(" "));
  await page.click("button[type=submit]");
  await page.fill("#new-password", "reset by recovery key");
  await page.click("button[type=submit]");
  await expect(page.locator("h1")).toHaveText("Sign in");

  await page.fill("#email", account.email);
  await page.fill("#password", "reset by recovery key");
  await page.click("button[type=submit]");
  await expect(page.locator("h1")).toHaveText("Your account");
  expect(violations).toEqual([]);
});
