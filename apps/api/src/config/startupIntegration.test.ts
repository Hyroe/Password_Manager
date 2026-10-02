import { afterEach, describe, expect, it, vi } from 'vitest';

import { createApp } from '../app.js';

import type { EmailSender } from '../modules/accounts/emailSender.js';

afterEach(() => {
  vi.unstubAllEnvs();
});

function stubProductionEnvironment(): void {
  vi.stubEnv('NODE_ENV', 'production');

  vi.stubEnv('WEBAUTHN_RP_ID', 'example.com');

  vi.stubEnv('WEBAUTHN_ORIGIN', 'https://vault.example.com');
}

describe('production application startup', () => {
  it('fails closed when no production email sender is configured', () => {
    stubProductionEnvironment();

    expect(() => createApp()).toThrow('Production-safe email delivery is required in production.');
  });

  it('allows application creation with an explicitly production-safe sender', () => {
    stubProductionEnvironment();

    const emailSender: EmailSender = {
      productionSafe: true,

      async sendVerificationEmail() {},
    };

    expect(() =>
      createApp({
        emailSender,
      }),
    ).not.toThrow();
  });
});
