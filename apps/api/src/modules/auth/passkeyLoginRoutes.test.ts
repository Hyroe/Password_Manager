import request from 'supertest';

import { afterAll, beforeEach, describe, expect, it } from 'vitest';

import { createApp } from '../../app.js';
import { prisma } from '../../lib/prisma.js';

import type { PasskeyAuthenticationProvider } from './passkeyAuthenticationProvider.js';

const authenticationProvider: PasskeyAuthenticationProvider = {
  async generateAuthenticationOptions() {
    return {
      challenge: 'test-login-challenge',

      timeout: 60_000,

      rpId: 'localhost',

      allowCredentials: [],

      userVerification: 'required',

      extensions: {},
    };
  },

  async verifyAuthenticationResponse() {
    return {
      newCounter: 1,
    };
  },
};

const app = createApp({
  passkeyAuthenticationProvider: authenticationProvider,
});

describe('passkey login', () => {
  beforeEach(async () => {
    await prisma.session.deleteMany();

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

  async function createActiveUser() {
    const user = await prisma.user.create({
      data: {
        email: 'login@example.com',

        normalizedEmail: 'login@example.com',

        status: 'ACTIVE',

        emailVerifiedAt: new Date(),

        webauthnUserId: 'test-webauthn-user-id',
      },
    });

    const passkey = await prisma.passkeyCredential.create({
      data: {
        userId: user.id,

        credentialId: 'login-credential',

        publicKey: new Uint8Array([1, 2, 3, 4]),

        counter: 0n,

        deviceType: 'singleDevice',

        backedUp: false,

        transports: ['internal'],
      },
    });

    return {
      user,
      passkey,
    };
  }

  it('creates discoverable passkey login options', async () => {
    const response = await request(app).post('/api/v1/auth/passkeys/login/options').send({});

    expect(response.status).toBe(200);

    expect(response.body.challengeId).toBeTypeOf('string');

    expect(response.body.options.challenge).toBe('test-login-challenge');

    const challenge = await prisma.webAuthnChallenge.findUnique({
      where: {
        id: response.body.challengeId,
      },
    });

    expect(challenge?.purpose).toBe('LOGIN');

    expect(challenge?.registrationAttemptId).toBeNull();
  });

  it('creates an opaque session after passkey authentication', async () => {
    const { user, passkey } = await createActiveUser();

    const options = await request(app).post('/api/v1/auth/passkeys/login/options').send({});

    const response = await request(app)
      .post('/api/v1/auth/passkeys/login/verify')
      .send({
        challengeId: options.body.challengeId,

        credential: {
          id: passkey.credentialId,
        },
      });

    expect(response.status).toBe(200);

    expect(response.body).toMatchObject({
      user: {
        id: user.id,
        email: 'login@example.com',
      },

      state: 'AUTHENTICATED_LOCKED',
    });

    /*
     * Raw session token must NOT be
     * exposed in JSON.
     */
    expect(response.body.sessionToken).toBeUndefined();

    const setCookieHeader = response.headers['set-cookie'];

    expect(setCookieHeader).toBeDefined();

    const cookies = Array.isArray(setCookieHeader)
      ? setCookieHeader.join(';')
      : (setCookieHeader ?? '');

    expect(cookies).toContain('pm_session=');
    expect(cookies).toContain('HttpOnly');
    expect(cookies).toContain('SameSite=Strict');

    const sessions = await prisma.session.findMany({
      where: {
        userId: user.id,
      },
    });

    expect(sessions).toHaveLength(1);

    expect(sessions[0]?.tokenHash).toBeDefined();

    const updatedPasskey = await prisma.passkeyCredential.findUniqueOrThrow({
      where: {
        id: passkey.id,
      },
    });

    expect(updatedPasskey.counter).toBe(1n);

    expect(updatedPasskey.lastUsedAt).not.toBeNull();
  });

  it('does not allow a login challenge to be reused', async () => {
    const { passkey } = await createActiveUser();

    const options = await request(app).post('/api/v1/auth/passkeys/login/options').send({});

    const payload = {
      challengeId: options.body.challengeId,

      credential: {
        id: passkey.credentialId,
      },
    };

    const first = await request(app).post('/api/v1/auth/passkeys/login/verify').send(payload);

    expect(first.status).toBe(200);

    const second = await request(app).post('/api/v1/auth/passkeys/login/verify').send(payload);

    expect(second.status).toBe(401);

    expect(await prisma.session.count()).toBe(1);
  });

  it('rejects an unknown credential', async () => {
    await createActiveUser();

    const options = await request(app).post('/api/v1/auth/passkeys/login/options').send({});

    const response = await request(app)
      .post('/api/v1/auth/passkeys/login/verify')
      .send({
        challengeId: options.body.challengeId,

        credential: {
          id: 'unknown-credential',
        },
      });

    expect(response.status).toBe(401);

    expect(response.body.error.code).toBe('AUTHENTICATION_FAILED');

    expect(await prisma.session.count()).toBe(0);
  });
});
