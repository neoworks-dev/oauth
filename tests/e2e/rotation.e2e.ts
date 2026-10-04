import { expect, test } from "@playwright/test";
import { collectViolations, newAccount, signIn, signUp, verifyEmailForReset } from "./helpers";

test("replacing the account key issues a new recovery key and retires the old one", async ({ page }) => {
  const violations = collectViolations(page);
  const account = newAccount();
  await signUp(page, account);
  const oldWords = [...account.recoveryWords];

  await page.fill("#rotate-password", account.password);
  await page.click("text=Create new keys");
  await expect(page.locator("h1")).toHaveText("Save your recovery key");
  const newWords = await page.locator("#recovery-words div").evaluateAll((items) =>
    items.map((item) => (item.textContent || "").replace(/^\d+\./, "").trim()));
  expect(newWords).toHaveLength(24);
  expect(newWords).not.toEqual(oldWords);
  await page.check("#recovery-confirm");
  await page.click("#confirm-recovery");
  await expect(page.locator("h1")).toHaveText("Your account");

  await page.click("#sign-out");
  await page.goto("/signin");
  await signIn(page, account);
  await expect(page.locator("h1")).toHaveText("Your account");
  await page.click("#sign-out");

  // The old recovery key no longer opens the account.
  await verifyEmailForReset(page, account);
  await page.fill("#recovery-words-input", oldWords.join(" "));
  await page.click("button[type=submit]");
  await expect(page.locator(".error:visible")).toBeVisible();

  await page.fill("#recovery-words-input", newWords.join(" "));
  await page.click("button[type=submit]");
  await expect(page.locator("h1")).toHaveText("Choose a new password");
  expect(violations).toEqual([]);
});

test("a wrong password stops a rotation before anything is sent", async ({ page }) => {
  const account = newAccount();
  await signUp(page, account);
  await page.fill("#rotate-password", "wrong password");
  await page.click("text=Create new keys");
  await expect(page.locator(".error:visible")).toBeVisible();
  await expect(page.locator("h1")).toHaveText("Your account");
});
