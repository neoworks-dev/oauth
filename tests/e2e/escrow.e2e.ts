import { expect, test } from "@playwright/test";
import { collectViolations, latestMail, newAccount, signIn, signUp, verifyEmailForReset } from "./helpers";

const waitingPeriodMs = 3_500;

test("signup offers two escrow options and recommends keeping the key to yourself", async ({ page }) => {
  await page.goto("/signup");
  await page.fill("#first-name", "Ada");
  await page.fill("#last-name", "Lovelace");
  await page.fill("#email", newAccount().email);
  await page.fill("#password", "correct horse battery");
  await page.click("button[type=submit]");
  const code = (await page.locator("#debug-code").textContent())!.replace(/\D/g, "");
  await page.fill("#code", code);
  await page.click("button[type=submit]");
  await expect(page.locator("#escrow-none")).toBeChecked();
  await expect(page.locator("text=Only you can unlock (recommended)")).toBeVisible();
  await expect(page.locator("text=Nobody can read it, not even us.")).toBeVisible();
  await expect(page.locator("text=Neoworks can help you recover")).toBeVisible();
  await expect(page.locator("text=could decrypt your data")).toBeVisible();
});

test("recovery with Neoworks's help waits, can be completed and sets a new password", async ({ page }) => {
  const violations = collectViolations(page);
  const account = newAccount();
  await signUp(page, account, { remember: false, escrow: true });
  await expect(page.locator("#escrow-body")).toContainText("Neoworks can help you recover");
  await page.click("#sign-out");

  await verifyEmailForReset(page, account);
  await page.click("#escrow-recover");
  await expect(page.locator("#escrow-status")).toContainText("We emailed you");
  const notice = await latestMail(page, account.email);
  expect(notice.subject).toBe("Account recovery requested");
  expect(notice.text).toContain("/recover/cancel#a=");

  // Too early: the wait has not ended.
  await page.click("#escrow-recover");
  await expect(page.locator("#escrow-status")).toContainText("Please come back");

  await page.waitForTimeout(waitingPeriodMs);
  await verifyEmailForReset(page, account);
  await page.click("#escrow-recover");
  await page.fill("#new-password", "chosen after escrow recovery");
  await page.click("button[type=submit]");
  await expect(page.locator("h1")).toHaveText("Sign in");

  await page.fill("#email", account.email);
  await page.fill("#password", "chosen after escrow recovery");
  await page.click("button[type=submit]");
  await expect(page.locator("h1")).toHaveText("Your account");
  expect(violations).toEqual([]);
});

test("the emailed cancel link stops a recovery", async ({ page }) => {
  const account = newAccount();
  await signUp(page, account, { remember: false, escrow: true });
  await page.click("#sign-out");
  await verifyEmailForReset(page, account);
  await page.click("#escrow-recover");
  await expect(page.locator("#escrow-status")).toContainText("We emailed you");

  const notice = await latestMail(page, account.email);
  const link = notice.text.split("\n").find((line) => line.includes("/recover/cancel#"))!;
  await page.goto(link.trim());
  await page.click("#cancel-recovery");
  await expect(page.locator("#cancel-result")).toContainText("cancelled");

  await page.waitForTimeout(waitingPeriodMs);
  await verifyEmailForReset(page, account);
  await page.click("#escrow-recover");
  await expect(page.locator(".error:visible")).toBeVisible();
});

test("a signed-in device sees and cancels a pending recovery", async ({ browser, page }) => {
  const account = newAccount();
  await signUp(page, account, { remember: true, escrow: true });

  const stranger = await browser.newPage();
  await verifyEmailForReset(stranger, account);
  await stranger.click("#escrow-recover");
  await expect(stranger.locator("#escrow-status")).toContainText("We emailed you");

  await page.reload();
  await expect(page.locator("#pending-recovery")).toBeVisible();
  await page.locator("#pending-recovery button").click();
  await expect(page.locator("#pending-recovery")).toHaveCount(0);
  await stranger.close();
});

test("escrow can be turned on later and turned off by replacing the key", async ({ page }) => {
  const violations = collectViolations(page);
  const account = newAccount();
  await signUp(page, account);
  await expect(page.locator("#escrow-body")).toContainText("Only you can unlock");

  await page.fill("#escrow-password", account.password);
  await page.click("text=Let Neoworks help me recover");
  await expect(page.locator("#escrow-body")).toContainText("Turning this off replaces your account key");

  await page.fill("#escrow-password", account.password);
  await page.click("text=Turn off recovery help");
  await expect(page.locator("h1")).toHaveText("Save your recovery key");
  await page.check("#recovery-confirm");
  // Turning escrow off is a full rotation: the identity changes and the link to the old one is sent.
  const completion = page.waitForRequest((request) => request.url().endsWith("/vault/rotate/complete"));
  await page.click("#confirm-recovery");
  expect((await completion).postDataJSON().rotationSig).toMatch(/^[A-Za-z0-9_-]{86}$/);
  await expect(page.locator("h1")).toHaveText("Your account");
  await expect(page.locator("#escrow-body")).toContainText("Only you can unlock");

  await page.click("#sign-out");
  await page.goto("/signin");
  await signIn(page, account);
  await expect(page.locator("h1")).toHaveText("Your account");
  expect(violations).toEqual([]);
});
