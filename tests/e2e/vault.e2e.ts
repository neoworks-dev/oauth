import { expect, test } from "@playwright/test";
import { authenticatorToken, collectViolations, newAccount, signUp } from "./helpers";

test("the page forbids injected script and HTML sinks", async ({ page }) => {
  await page.goto("/signin");
  const results = await page.evaluate(() => {
    const outcomes: Record<string, string> = {};
    try {
      document.body.innerHTML = "<b>x</b>";
      outcomes.innerHTML = "allowed";
    } catch (error) {
      outcomes.innerHTML = "blocked";
    }
    try {
      const script = document.createElement("script");
      script.textContent = "window.injected = true";
      document.body.append(script);
      outcomes.inline = (window as any).injected ? "allowed" : "blocked";
    } catch (error) {
      outcomes.inline = "blocked";
    }
    return outcomes;
  });
  expect(results).toEqual({ innerHTML: "blocked", inline: "blocked" });
});

test("the vault cannot be framed and sets hardening headers", async ({ page }) => {
  const response = await page.goto("/signin");
  const headers = response!.headers();
  expect(headers["content-security-policy"]).toContain("frame-ancestors 'none'");
  expect(headers["content-security-policy"]).toContain("require-trusted-types-for 'script'");
  expect(headers["x-frame-options"]).toBe("DENY");
  expect(headers["cross-origin-opener-policy"]).toBe("same-origin");
});

test("the AMK handover unlocks a browser from the authenticator", async ({ page }) => {
  const violations = collectViolations(page);
  const account = newAccount();
  await signUp(page, account, { remember: false, escrow: false });
  await page.reload();
  await expect(page.locator("h1")).toHaveText("Unlock your account");

  await page.click("#unlock-authenticator");
  const qr = page.locator(".handover-qr");
  await expect(qr).toBeVisible();
  const payloadText = new URL((await qr.getAttribute("src"))!, page.url()).searchParams.get("p")!;
  expect(payloadText.startsWith("nwh1:")).toBe(true);
  const payload = JSON.parse(Buffer.from(payloadText.slice(5), "base64url").toString());
  expect(payload.v).toBe(1);

  // Act as the authenticator: it knows the AMK and has a token of its own client.
  const token = await authenticatorToken(page.context());
  const status = await page.evaluate(async ({ handover, password, token }) => {
    const account = await import("/static/vault/nw-account.js");
    const primitives = await import("/static/vault/nw-primitives.js");
    const bundle = await (await fetch("/vault/bundle")).json();
    const keys = account.derivePasswordKeys(password, { salt: bundle.pwhashSalt, ops: bundle.pwhashOps, mem: bundle.pwhashMem });
    const amk = account.unwrapAmk(keys.passwordKEK, primitives.decodeBase64Url(bundle.amkPassword), bundle.userId, "password");
    const sealed = primitives.seal(primitives.decodeBase64Url(handover.tempPub), amk);
    const reply = await fetch("/vault/handover/" + handover.sessionId, {
      method: "POST",
      headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
      body: JSON.stringify({ userId: bundle.userId, deviceId: crypto.randomUUID(), sealed: primitives.encodeBase64Url(sealed) }),
    });
    return reply.status;
  }, { handover: payload, password: account.password, token });
  expect(status).toBe(200);
  await expect(page.locator("h1")).toHaveText("Your account", { timeout: 30_000 });
  expect(violations).toEqual([]);
});
