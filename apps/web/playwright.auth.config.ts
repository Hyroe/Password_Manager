import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',

  testMatch: '**/passkey-auth.spec.ts',

  fullyParallel: false,

  workers: 1,

  timeout: 60_000,

  expect: {
    timeout: 10_000,
  },

  reporter: 'list',

  outputDir: 'test-results/passkey-auth',

  use: {
    baseURL: 'http://localhost:5173',

    trace: 'retain-on-failure',

    screenshot: 'only-on-failure',

    video: 'retain-on-failure',
  },

  webServer: {
    command: 'pnpm --filter @pm/web build && pnpm --filter @pm/api exec tsx src/e2eServer.ts',

    cwd: '../..',

    url: 'http://localhost:5173/api/v1/health',

    reuseExistingServer: false,

    timeout: 120_000,

    env: {
      ...process.env,

      NODE_ENV: 'test',

      PORT: '5173',
    },

    stdout: 'pipe',

    stderr: 'pipe',
  },

  projects: [
    {
      name: 'chromium-passkey',

      use: {
        ...devices['Desktop Chrome'],
      },
    },
  ],
});
