import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';

import { createApp } from '../../app.js';
import { prisma } from '../../lib/prisma.js';
import type { EmailSender, VerificationEmail } from './emailSender.js';

describe('account registration', () => {
  let verificationEmail: VerificationEmail | undefined;

  const emailSender: EmailSender = {
    async sendVerificationEmail(message) {
      verificationEmail = message;
    },
  };

  const app = createApp({
    emailSender,
  });

  beforeEach(async () => {
    verificationEmail = undefined;

    await prisma.vaultKeyEnvelope.deleteMany();
    await prisma.vault.deleteMany();

    await prisma.recoveryEnvelope.deleteMany();
    await prisma.rootKeyEnvelope.deleteMany();
    await prisma.userCryptoProfile.deleteMany();

    await prisma.passkeyCredential.deleteMany();

    await prisma.accountBootstrapContext.deleteMany();
    await prisma.webAuthnChallenge.deleteMany();
    await prisma.registrationPasskey.deleteMany();

    await prisma.registrationAttempt.deleteMany();
    await prisma.session.deleteMany();
    await prisma.user.deleteMany();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('starts an account registration', async () => {
    const response = await request(app).post('/api/v1/accounts').send({
      email: 'Daniel@example.com',
    });

    expect(response.status).toBe(202);
    expect(response.body.registrationId).toBeTypeOf('string');

    expect(verificationEmail).toBeDefined();
    expect(verificationEmail?.email).toBe('Daniel@example.com');

    const attempt = await prisma.registrationAttempt.findUnique({
      where: {
        id: response.body.registrationId,
      },
    });

    expect(attempt?.normalizedEmail).toBe('daniel@example.com');
    expect(attempt?.status).toBe('PENDING');
  });

  it('verifies the email and returns a temporary registration token', async () => {
    const startResponse = await request(app).post('/api/v1/accounts').send({
      email: 'daniel@example.com',
    });

    expect(verificationEmail).toBeDefined();

    const response = await request(app).post('/api/v1/accounts/verify-email').send({
      registrationId: startResponse.body.registrationId,
      token: verificationEmail!.token,
    });

    expect(response.status).toBe(200);
    expect(response.body.registrationToken).toBeTypeOf('string');

    const attempt = await prisma.registrationAttempt.findUnique({
      where: {
        id: startResponse.body.registrationId,
      },
    });

    expect(attempt?.status).toBe('EMAIL_VERIFIED');
    expect(attempt?.emailVerifiedAt).not.toBeNull();
    expect(attempt?.registrationTokenHash).not.toBeNull();
  });

  it('rejects reuse of the email verification token', async () => {
    const startResponse = await request(app).post('/api/v1/accounts').send({
      email: 'daniel@example.com',
    });

    const token = verificationEmail!.token;

    const firstResponse = await request(app).post('/api/v1/accounts/verify-email').send({
      registrationId: startResponse.body.registrationId,
      token,
    });

    expect(firstResponse.status).toBe(200);

    const secondResponse = await request(app).post('/api/v1/accounts/verify-email').send({
      registrationId: startResponse.body.registrationId,
      token,
    });

    expect(secondResponse.status).toBe(400);
    expect(secondResponse.body.error.code).toBe('REGISTRATION_INVALID');
  });

  it('rejects invalid email input', async () => {
    const response = await request(app).post('/api/v1/accounts').send({
      email: 'not-an-email',
    });

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
  });
});
