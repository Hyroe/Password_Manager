import type { AuthenticationResponseJSON } from '@simplewebauthn/server';

import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { PasskeyAuthenticationProvider } from './passkeyAuthenticationProvider.js';

const prismaMock = vi.hoisted(() => ({
  webAuthnChallenge: {
    findFirst: vi.fn(),
  },

  passkeyCredential: {
    findUnique: vi.fn(),
  },
}));

vi.mock('../../lib/prisma.js', () => ({
  prisma: prismaMock,
}));

import { verifyPasskeyLogin } from './passkeyLoginService.js';

const provider = {} as PasskeyAuthenticationProvider;

const credential = {
  id: 'unknown-credential',
} as AuthenticationResponseJSON;

describe('passkey login enumeration resistance', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('uses the same failure for an unknown challenge', async () => {
    prismaMock.webAuthnChallenge.findFirst.mockResolvedValue(null);

    await expect(
      verifyPasskeyLogin(
        'unknown-challenge',

        credential,

        provider,
      ),
    ).rejects.toThrow('AUTHENTICATION_FAILED');
  });

  it('uses the same failure for an unknown credential', async () => {
    prismaMock.webAuthnChallenge.findFirst.mockResolvedValue({
      id: 'challenge-id',

      purpose: 'LOGIN',

      challenge: 'challenge-value',

      usedAt: null,

      expiresAt: new Date(Date.now() + 60_000),
    });

    prismaMock.passkeyCredential.findUnique.mockResolvedValue(null);

    await expect(
      verifyPasskeyLogin(
        'challenge-id',

        credential,

        provider,
      ),
    ).rejects.toThrow('AUTHENTICATION_FAILED');
  });
});
