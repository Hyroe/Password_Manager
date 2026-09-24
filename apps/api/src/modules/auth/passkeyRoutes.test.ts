import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';

import { createApp } from '../../app.js';
import { prisma } from '../../lib/prisma.js';
import type { EmailSender, VerificationEmail } from '../accounts/emailSender.js';
import type { VerifiedPasskeyRegistration, WebAuthnProvider } from './webauthnProvider.js';

describe('passkey registration', () => {
  let verificationEmail: VerificationEmail | undefined;

  const emailSender: EmailSender = {
    async sendVerificationEmail(message) {
      verificationEmail = message;
    },
  };

  const webAuthnProvider: WebAuthnProvider = {
    async generateRegistrationOptions(input) {
      return {
        challenge: 'test-challenge',
        rp: {
          name: 'Password Manager',
          id: 'localhost',
        },
        user: {
          id: Buffer.from(input.userID).toString('base64url'),
          name: input.userName,
          displayName: input.userDisplayName,
        },
        pubKeyCredParams: [
          {
            alg: -7,
            type: 'public-key',
          },
        ],
        timeout: 60000,
        attestation: 'none',
        excludeCredentials: [],
        authenticatorSelection: {
          residentKey: 'required',
          userVerification: 'required',
        },
        extensions: {},
      };
    },

    async verifyRegistrationResponse(): Promise<VerifiedPasskeyRegistration> {
      return {
        credential: {
          id: 'credential-id',
          publicKey: new Uint8Array([1, 2, 3, 4]),
          counter: 0,
          transports: ['internal'],
        },
        deviceType: 'multiDevice',
        backedUp: true,
      };
    },
  };

  const app = createApp({
    emailSender,
    webAuthnProvider,
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
    await prisma.user.deleteMany();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('creates WebAuthn registration options', async () => {
    const startResponse = await request(app).post('/api/v1/accounts').send({
      email: 'daniel@example.com',
    });

    const verifyResponse = await request(app).post('/api/v1/accounts/verify-email').send({
      registrationId: startResponse.body.registrationId,
      token: verificationEmail!.token,
    });

    const response = await request(app).post('/api/v1/auth/passkeys/register/options').send({
      registrationId: startResponse.body.registrationId,
      registrationToken: verifyResponse.body.registrationToken,
    });

    expect(response.status).toBe(200);
    expect(response.body.challengeId).toBeTypeOf('string');
    expect(response.body.options.challenge).toBe('test-challenge');

    const attempt = await prisma.registrationAttempt.findUniqueOrThrow({
      where: {
        id: startResponse.body.registrationId,
      },
    });

    expect(attempt.webauthnUserId).not.toBeNull();
  });

  it('verifies and stores the first passkey', async () => {
    const startResponse = await request(app).post('/api/v1/accounts').send({
      email: 'daniel@example.com',
    });

    const emailResponse = await request(app).post('/api/v1/accounts/verify-email').send({
      registrationId: startResponse.body.registrationId,
      token: verificationEmail!.token,
    });

    const optionsResponse = await request(app).post('/api/v1/auth/passkeys/register/options').send({
      registrationId: startResponse.body.registrationId,
      registrationToken: emailResponse.body.registrationToken,
    });

    const response = await request(app).post('/api/v1/auth/passkeys/register/verify').send({
      registrationId: startResponse.body.registrationId,
      registrationToken: emailResponse.body.registrationToken,
      challengeId: optionsResponse.body.challengeId,
      credential: {},
    });

    expect(response.status).toBe(200);
    expect(response.body.bootstrapToken).toBeTypeOf('string');

    const attempt = await prisma.registrationAttempt.findUniqueOrThrow({
      where: {
        id: startResponse.body.registrationId,
      },
    });

    expect(attempt.status).toBe('PASSKEY_REGISTERED');
    expect(attempt.bootstrapTokenHash).not.toBeNull();

    const passkey = await prisma.registrationPasskey.findFirst({
      where: {
        registrationAttemptId: attempt.id,
      },
    });

    expect(passkey).not.toBeNull();
    expect(passkey?.credentialId).toBe('credential-id');
    expect(passkey?.publicKey).toEqual(new Uint8Array([1, 2, 3, 4]));
  });

  it('does not allow a WebAuthn challenge to be reused', async () => {
    const startResponse = await request(app).post('/api/v1/accounts').send({
      email: 'daniel@example.com',
    });

    const emailResponse = await request(app).post('/api/v1/accounts/verify-email').send({
      registrationId: startResponse.body.registrationId,
      token: verificationEmail!.token,
    });

    const optionsResponse = await request(app).post('/api/v1/auth/passkeys/register/options').send({
      registrationId: startResponse.body.registrationId,
      registrationToken: emailResponse.body.registrationToken,
    });

    const payload = {
      registrationId: startResponse.body.registrationId,
      registrationToken: emailResponse.body.registrationToken,
      challengeId: optionsResponse.body.challengeId,
      credential: {},
    };

    const firstResponse = await request(app)
      .post('/api/v1/auth/passkeys/register/verify')
      .send(payload);

    expect(firstResponse.status).toBe(200);

    const secondResponse = await request(app)
      .post('/api/v1/auth/passkeys/register/verify')
      .send(payload);

    expect(secondResponse.status).toBe(400);
  });

  it('rejects passkey options with an invalid registration token', async () => {
    const startResponse = await request(app).post('/api/v1/accounts').send({
      email: 'daniel@example.com',
    });

    await request(app).post('/api/v1/accounts/verify-email').send({
      registrationId: startResponse.body.registrationId,
      token: verificationEmail!.token,
    });

    const response = await request(app).post('/api/v1/auth/passkeys/register/options').send({
      registrationId: startResponse.body.registrationId,
      registrationToken: 'invalid-token',
    });

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('REGISTRATION_INVALID');
  });
});
