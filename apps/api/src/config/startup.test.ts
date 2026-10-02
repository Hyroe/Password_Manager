import { describe, expect, it } from 'vitest';

import type { EmailSender } from '../modules/accounts/emailSender.js';

import type { Environment } from './env.js';

import { assertRuntimeDependencies } from './startup.js';

function environment(nodeEnvironment: Environment['NODE_ENV']): Environment {
  return {
    NODE_ENV: nodeEnvironment,

    PORT: 3000,

    DATABASE_URL: 'postgresql://user:password@localhost:5432/database',

    WEBAUTHN_RP_NAME: 'Password Manager',

    WEBAUTHN_RP_ID: nodeEnvironment === 'production' ? 'example.com' : 'localhost',

    WEBAUTHN_ORIGIN:
      nodeEnvironment === 'production' ? 'https://vault.example.com' : 'http://localhost:5173',

    TRUST_PROXY_HOPS: undefined,
  };
}

const unsafeSender: EmailSender = {
  productionSafe: false,

  async sendVerificationEmail() {},
};

const productionSender: EmailSender = {
  productionSafe: true,

  async sendVerificationEmail() {},
};

describe('runtime dependency validation', () => {
  it('allows development-only email delivery outside production', () => {
    expect(() =>
      assertRuntimeDependencies(environment('development'), {
        emailSender: unsafeSender,
      }),
    ).not.toThrow();
  });

  it('allows test email delivery outside production', () => {
    expect(() =>
      assertRuntimeDependencies(environment('test'), {
        emailSender: unsafeSender,
      }),
    ).not.toThrow();
  });

  it('rejects an email sender that is not explicitly production safe', () => {
    expect(() =>
      assertRuntimeDependencies(environment('production'), {
        emailSender: unsafeSender,
      }),
    ).toThrow('Production-safe email delivery is required in production.');
  });

  it('rejects an email sender with no production declaration', () => {
    const undeclaredSender: EmailSender = {
      async sendVerificationEmail() {},
    };

    expect(() =>
      assertRuntimeDependencies(environment('production'), {
        emailSender: undeclaredSender,
      }),
    ).toThrow('Production-safe email delivery is required in production.');
  });

  it('accepts an explicitly production-safe email sender', () => {
    expect(() =>
      assertRuntimeDependencies(environment('production'), {
        emailSender: productionSender,
      }),
    ).not.toThrow();
  });
});
