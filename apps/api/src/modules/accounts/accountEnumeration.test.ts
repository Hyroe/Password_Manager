import express from 'express';

import request from 'supertest';

import { beforeEach, describe, expect, it, vi } from 'vitest';

import { generateSecurityToken, hashSecurityToken } from '../../lib/securityTokens.js';

const prismaMock = vi.hoisted(() => ({
  registrationAttempt: {
    create: vi.fn(),
    findUnique: vi.fn(),
    update: vi.fn(),
  },

  user: {
    findUnique: vi.fn(),
  },
}));

vi.mock('../../lib/prisma.js', () => ({
  prisma: prismaMock,
}));

import { createAccountController } from './accountController.js';

const sendVerificationEmail = vi.fn(async () => undefined);

function createTestApp() {
  const app = express();

  app.use(express.json());

  const controller = createAccountController({
    sendVerificationEmail,
  });

  app.post('/accounts', controller.start);

  app.post('/accounts/verify-email', controller.verifyEmail);

  return app;
}

describe('account enumeration resistance', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('does not query account existence during registration start', async () => {
    prismaMock.registrationAttempt.create.mockResolvedValue({
      id: '11111111-1111-4111-8111-111111111111',
    });

    const response = await request(createTestApp())
      .post('/accounts')
      .send({
        email: 'target@example.com',
      })
      .expect(202);

    expect(response.body).toEqual({
      registrationId: '11111111-1111-4111-8111-111111111111',
    });

    /*
     * Registration start deliberately does not
     * branch on whether User already exists.
     */
    expect(prismaMock.user.findUnique).not.toHaveBeenCalled();

    expect(sendVerificationEmail).toHaveBeenCalledOnce();
  });

  it('returns the same external failure for an unknown registration and an existing account', async () => {
    const registrationId = '22222222-2222-4222-8222-222222222222';

    const token = generateSecurityToken();

    /*
     * First request:
     * registration attempt does not exist.
     */
    prismaMock.registrationAttempt.findUnique.mockResolvedValueOnce(null);

    const unknownAttempt = await request(createTestApp())
      .post('/accounts/verify-email')
      .send({
        registrationId,
        token,
      })
      .expect(400);

    /*
     * Second request:
     * verification token is genuinely valid,
     * but the normalized email already belongs
     * to an account.
     */
    prismaMock.registrationAttempt.findUnique.mockResolvedValueOnce({
      id: registrationId,

      status: 'PENDING',

      normalizedEmail: 'existing@example.com',

      emailTokenExpiresAt: new Date(Date.now() + 60_000),

      emailTokenHash: Uint8Array.from(hashSecurityToken(token)),
    });

    prismaMock.user.findUnique.mockResolvedValueOnce({
      id: 'existing-user',
    });

    const existingAccount = await request(createTestApp())
      .post('/accounts/verify-email')
      .send({
        registrationId,
        token,
      })
      .expect(400);

    expect(unknownAttempt.body).toEqual({
      error: {
        code: 'REGISTRATION_INVALID',

        message: 'The registration request is invalid or expired.',
      },
    });

    /*
     * Existing-account state must not be
     * distinguishable from an invalid attempt.
     */
    expect(existingAccount.body).toEqual(unknownAttempt.body);

    expect(prismaMock.registrationAttempt.update).not.toHaveBeenCalled();
  });
});
