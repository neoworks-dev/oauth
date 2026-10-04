import { defineConfig } from "@playwright/test";

// The origins are defined once here. Tests navigate with relative paths on the
// vault origin and read the oauth origin from OAUTH_ORIGIN.
const vaultOrigin = "http://localhost:18087";
const oauthOrigin = "http://localhost:18080";
process.env.OAUTH_ORIGIN = oauthOrigin;

export default defineConfig({
  testDir: "./e2e",
  testMatch: "**/*.e2e.ts",
  timeout: 90_000,
  expect: { timeout: 20_000 },
  fullyParallel: false,
  workers: 1,
  reporter: "list",
  use: {
    baseURL: vaultOrigin,
    launchOptions: { executablePath: process.env.CHROMIUM_PATH },
    trace: "retain-on-failure",
  },
  webServer: {
    command: "go run ./cmd/devstack -oauth-port=18080 -vault-port=18087",
    cwd: "..",
    url: vaultOrigin + "/signin",
    timeout: 120_000,
    reuseExistingServer: false,
  },
});
