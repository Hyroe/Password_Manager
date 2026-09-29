import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',

  fullyParallel: false,

  workers: 1,

  timeout: 30_000,

  expect: {
    timeout: 5_000,
  },

  reporter: 'list',

  outputDir: 'test-results',

  use: {
    baseURL: 'http://127.0.0.1:5173',

    trace: 'retain-on-failure',

    screenshot: 'only-on-failure',

    video: 'retain-on-failure',
  },

  webServer: {
    command: 'pnpm exec vite --host 127.0.0.1 --port 5173',

    url: 'http://127.0.0.1:5173/login',

    reuseExistingServer: true,

    timeout: 120_000,
  },

  projects: [
    {
      name: 'chromium',

      use: {
        ...devices['Desktop Chrome'],
      },
    },
  ],
});
