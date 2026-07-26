import { defineConfig, devices } from '@playwright/test';

// The binary is built by CI (or `make build`) before the tests run; override
// with CG_BIN when it lives elsewhere.
const bin = process.env.CG_BIN ?? '../cluster-guardian';

export default defineConfig({
  testDir: './tests',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: 'http://127.0.0.1:8099',
    trace: 'on-first-retry',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: `${bin} serve --fixture fixtures/run1.json --fixture fixtures/run2.json --listen 127.0.0.1:8099`,
    url: 'http://127.0.0.1:8099/healthz',
    reuseExistingServer: !process.env.CI,
  },
});
