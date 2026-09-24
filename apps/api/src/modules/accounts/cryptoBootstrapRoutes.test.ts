import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';

import { createApp } from '../../app.js';
import { prisma } from '../../lib/prisma.js';
import { generateSecurityToken, hashSecurityToken } from '../../lib/securityTokens.js';

describe('crypto bootstrap options', () => {
  const app = createApp();

  beforeEach(async () => {
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

  function base64UrlBytes(length: number, fill: number): string {
    return Buffer.alloc(length, fill).toString('base64url');
  }

  async function createBootstrapReadyRegistration() {
    const bootstrapToken = generateSecurityToken();

    const attempt = await prisma.registrationAttempt.create({
      data: {
        email: 'complete@example.com',
        normalizedEmail: 'complete@example.com',

        status: 'PASSKEY_REGISTERED',

        emailTokenHash: new Uint8Array(hashSecurityToken(generateSecurityToken())),

        emailTokenExpiresAt: new Date(Date.now() + 15 * 60 * 1000),

        emailVerifiedAt: new Date(),

        webauthnUserId: generateSecurityToken(),

        bootstrapTokenHash: new Uint8Array(hashSecurityToken(bootstrapToken)),

        bootstrapTokenExpiresAt: new Date(Date.now() + 15 * 60 * 1000),
      },
    });

    await prisma.registrationPasskey.create({
      data: {
        registrationAttemptId: attempt.id,

        credentialId: `credential-${attempt.id}`,

        publicKey: new Uint8Array([1, 2, 3, 4]),

        counter: 0n,

        webauthnUserId: attempt.webauthnUserId!,

        deviceType: 'singleDevice',

        backedUp: false,

        transports: ['internal'],
      },
    });

    const options = await request(app).post('/api/v1/accounts/crypto/options').send({
      registrationId: attempt.id,
      bootstrapToken,
    });

    expect(options.status).toBe(200);

    return {
      attempt,
      bootstrapToken,
      options: options.body,
    };
  }

  async function createPasskeyRegisteredAttempt() {
    const bootstrapToken = generateSecurityToken();

    const attempt = await prisma.registrationAttempt.create({
      data: {
        email: 'bootstrap@example.com',
        normalizedEmail: 'bootstrap@example.com',

        status: 'PASSKEY_REGISTERED',

        emailTokenHash: new Uint8Array(hashSecurityToken(generateSecurityToken())),

        emailTokenExpiresAt: new Date(Date.now() + 15 * 60 * 1000),

        emailVerifiedAt: new Date(),

        webauthnUserId: generateSecurityToken(),

        bootstrapTokenHash: new Uint8Array(hashSecurityToken(bootstrapToken)),

        bootstrapTokenExpiresAt: new Date(Date.now() + 15 * 60 * 1000),
      },
    });

    return {
      attempt,
      bootstrapToken,
    };
  }

  it('creates an account bootstrap context', async () => {
    const { attempt, bootstrapToken } = await createPasskeyRegisteredAttempt();

    const response = await request(app).post('/api/v1/accounts/crypto/options').send({
      registrationId: attempt.id,
      bootstrapToken,
    });

    expect(response.status).toBe(200);

    expect(response.body.bootstrapContextId).toBeTypeOf('string');

    expect(response.body.cryptoProfileId).toBeTypeOf('string');

    expect(response.body.vaultId).toBeTypeOf('string');

    expect(response.body.protocolVersion).toBe(1);

    expect(response.body.kdf).toEqual({
      algorithm: 'ARGON2ID',
      profileVersion: 1,
      memoryKib: 19 * 1024,
      iterations: 2,
      parallelism: 1,
      saltBytes: 16,
    });

    expect(response.body.envelope.version).toBe(1);

    const context = await prisma.accountBootstrapContext.findUnique({
      where: {
        registrationAttemptId: attempt.id,
      },
    });

    expect(context).not.toBeNull();
  });

  it('returns the same active bootstrap context', async () => {
    const { attempt, bootstrapToken } = await createPasskeyRegisteredAttempt();

    const first = await request(app).post('/api/v1/accounts/crypto/options').send({
      registrationId: attempt.id,
      bootstrapToken,
    });

    const second = await request(app).post('/api/v1/accounts/crypto/options').send({
      registrationId: attempt.id,
      bootstrapToken,
    });

    expect(second.status).toBe(200);

    expect(second.body.bootstrapContextId).toBe(first.body.bootstrapContextId);

    expect(second.body.cryptoProfileId).toBe(first.body.cryptoProfileId);

    expect(second.body.vaultId).toBe(first.body.vaultId);
  });

  it('binds AAD to the reserved crypto identifiers', async () => {
    const { attempt, bootstrapToken } = await createPasskeyRegisteredAttempt();

    const response = await request(app).post('/api/v1/accounts/crypto/options').send({
      registrationId: attempt.id,
      bootstrapToken,
    });

    expect(response.status).toBe(200);

    expect(response.body.envelope.rootKeyAad).toBe(
      `pm:v1:ark:crypto-profile:${response.body.cryptoProfileId}:key-version:1`,
    );

    expect(response.body.envelope.recoveryRootKeyAad).toBe(
      `pm:v1:recovery-ark:crypto-profile:${response.body.cryptoProfileId}:key-version:1`,
    );

    expect(response.body.envelope.vaultKeyAad).toBe(
      `pm:v1:pvk:vault:${response.body.vaultId}:key-version:1`,
    );
  });

  it('rejects an invalid bootstrap token', async () => {
    const { attempt } = await createPasskeyRegisteredAttempt();

    const response = await request(app).post('/api/v1/accounts/crypto/options').send({
      registrationId: attempt.id,
      bootstrapToken: 'invalid-token',
    });

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('BOOTSTRAP_INVALID');
  });
  it('atomically activates an account from encrypted bootstrap material', async () => {
    const { attempt, bootstrapToken, options } = await createBootstrapReadyRegistration();

    const response = await request(app)
      .post('/api/v1/accounts/crypto/complete')
      .send({
        registrationId: attempt.id,
        bootstrapToken,
        bootstrapContextId: options.bootstrapContextId,

        protocolVersion: 1,

        kdf: {
          algorithm: 'ARGON2ID',
          profileVersion: 1,

          memoryKib: 19 * 1024,
          iterations: 2,
          parallelism: 1,

          salt: base64UrlBytes(16, 0x11),
        },

        envelope: {
          version: 1,

          rootKey: base64UrlBytes(61, 0x22),

          recoveryRootKey: base64UrlBytes(61, 0x33),

          vaultKey: base64UrlBytes(61, 0x44),
        },
      });

    expect(response.status).toBe(201);
    expect(response.body.userId).toBeTypeOf('string');
    expect(response.body.vaultId).toBe(options.vaultId);
    expect(response.body.status).toBe('ACTIVE');

    const user = await prisma.user.findUniqueOrThrow({
      where: {
        id: response.body.userId,
      },
    });

    expect(user.status).toBe('ACTIVE');
    expect(user.normalizedEmail).toBe(attempt.normalizedEmail);

    const profile = await prisma.userCryptoProfile.findUniqueOrThrow({
      where: {
        userId: user.id,
      },
    });

    expect(profile.id).toBe(options.cryptoProfileId);

    expect(profile.protocolVersion).toBe(1);
    expect(profile.kdfAlgorithm).toBe('ARGON2ID');

    expect(Array.from(profile.kdfSalt)).toEqual(Array.from(Buffer.alloc(16, 0x11)));

    const rootEnvelope = await prisma.rootKeyEnvelope.findFirstOrThrow({
      where: {
        cryptoProfileId: profile.id,
      },
    });

    expect(rootEnvelope.encryptedKey.length).toBe(61);

    const recoveryEnvelope = await prisma.recoveryEnvelope.findFirstOrThrow({
      where: {
        cryptoProfileId: profile.id,
      },
    });

    expect(recoveryEnvelope.encryptedKey.length).toBe(61);

    const vault = await prisma.vault.findUniqueOrThrow({
      where: {
        id: options.vaultId,
      },
    });

    expect(vault.userId).toBe(user.id);
    expect(vault.kind).toBe('PERSONAL');

    const vaultEnvelope = await prisma.vaultKeyEnvelope.findFirstOrThrow({
      where: {
        vaultId: vault.id,
      },
    });

    expect(vaultEnvelope.encryptedKey.length).toBe(61);

    const passkey = await prisma.passkeyCredential.findFirst({
      where: {
        userId: user.id,
      },
    });

    expect(passkey).not.toBeNull();

    const temporaryPasskeys = await prisma.registrationPasskey.count({
      where: {
        registrationAttemptId: attempt.id,
      },
    });

    expect(temporaryPasskeys).toBe(0);

    const completedAttempt = await prisma.registrationAttempt.findUniqueOrThrow({
      where: {
        id: attempt.id,
      },
    });

    expect(completedAttempt.status).toBe('COMPLETED');

    expect(completedAttempt.completedUserId).toBe(user.id);

    expect(completedAttempt.completedAt).not.toBeNull();
  });
  it('returns the same account when completion is retried', async () => {
    const { attempt, bootstrapToken, options } = await createBootstrapReadyRegistration();

    const payload = {
      registrationId: attempt.id,
      bootstrapToken,
      bootstrapContextId: options.bootstrapContextId,

      protocolVersion: 1,

      kdf: {
        algorithm: 'ARGON2ID',
        profileVersion: 1,

        memoryKib: 19 * 1024,
        iterations: 2,
        parallelism: 1,

        salt: base64UrlBytes(16, 0x11),
      },

      envelope: {
        version: 1,

        rootKey: base64UrlBytes(61, 0x22),

        recoveryRootKey: base64UrlBytes(61, 0x33),

        vaultKey: base64UrlBytes(61, 0x44),
      },
    };

    const first = await request(app).post('/api/v1/accounts/crypto/complete').send(payload);

    expect(first.status).toBe(201);

    const second = await request(app).post('/api/v1/accounts/crypto/complete').send(payload);

    expect(second.status).toBe(200);

    expect(second.body.userId).toBe(first.body.userId);

    expect(second.body.vaultId).toBe(first.body.vaultId);

    expect(
      await prisma.user.count({
        where: {
          normalizedEmail: attempt.normalizedEmail,
        },
      }),
    ).toBe(1);
  });
  it('rejects malformed encrypted bootstrap material', async () => {
    const { attempt, bootstrapToken, options } = await createBootstrapReadyRegistration();

    const response = await request(app)
      .post('/api/v1/accounts/crypto/complete')
      .send({
        registrationId: attempt.id,
        bootstrapToken,

        bootstrapContextId: options.bootstrapContextId,

        protocolVersion: 1,

        kdf: {
          algorithm: 'ARGON2ID',
          profileVersion: 1,
          memoryKib: 19 * 1024,
          iterations: 2,
          parallelism: 1,

          salt: base64UrlBytes(16, 0x11),
        },

        envelope: {
          version: 1,

          rootKey: base64UrlBytes(10, 0x22),

          recoveryRootKey: base64UrlBytes(61, 0x33),

          vaultKey: base64UrlBytes(61, 0x44),
        },
      });

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('BOOTSTRAP_INVALID');

    expect(await prisma.user.count()).toBe(0);
  });
});
