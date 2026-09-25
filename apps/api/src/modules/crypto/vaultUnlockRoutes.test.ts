import request from 'supertest';

import { afterAll, beforeEach, describe, expect, it } from 'vitest';

import { createApp } from '../../app.js';

import { SESSION_ABSOLUTE_TTL_MS, SESSION_IDLE_TTL_MS } from '../../config/session.js';

import { prisma } from '../../lib/prisma.js';

import { generateSecurityToken, hashSecurityToken } from '../../lib/securityTokens.js';

const app = createApp();

describe('vault unlock bootstrap', () => {
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
    await prisma.user.deleteMany();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  async function createUnlockableAccount() {
    const user = await prisma.user.create({
      data: {
        email: 'unlock@example.com',

        normalizedEmail: 'unlock@example.com',

        status: 'ACTIVE',

        emailVerifiedAt: new Date(),

        webauthnUserId: 'unlock-webauthn-user',
      },
    });

    const cryptoProfileId = '0199c531-a830-7000-8000-000000000001';

    const vaultId = '0199c531-a830-7000-8000-000000000002';

    await prisma.userCryptoProfile.create({
      data: {
        id: cryptoProfileId,

        userId: user.id,

        protocolVersion: 1,

        kdfAlgorithm: 'ARGON2ID',

        kdfProfileVersion: 1,

        argon2MemoryKib: 19 * 1024,

        argon2Iterations: 2,
        argon2Parallelism: 1,

        kdfSalt: new Uint8Array(16).fill(0x11),
      },
    });

    await prisma.rootKeyEnvelope.create({
      data: {
        cryptoProfileId,

        keyVersion: 1,
        envelopeVersion: 1,

        encryptedKey: new Uint8Array(61).fill(0x22),
      },
    });

    await prisma.vault.create({
      data: {
        id: vaultId,

        userId: user.id,

        kind: 'PERSONAL',
      },
    });

    await prisma.vaultKeyEnvelope.create({
      data: {
        vaultId,

        vaultKeyVersion: 1,
        rootKeyVersion: 1,

        envelopeVersion: 1,

        encryptedKey: new Uint8Array(61).fill(0x33),
      },
    });

    const token = generateSecurityToken();

    const now = new Date();

    await prisma.session.create({
      data: {
        userId: user.id,

        tokenHash: Uint8Array.from(hashSecurityToken(token)),

        idleExpiresAt: new Date(now.getTime() + SESSION_IDLE_TTL_MS),

        absoluteExpiresAt: new Date(now.getTime() + SESSION_ABSOLUTE_TTL_MS),
      },
    });

    return {
      user,
      token,
      cryptoProfileId,
      vaultId,
    };
  }

  it('returns encrypted material required to unlock the personal vault', async () => {
    const { token, cryptoProfileId, vaultId } = await createUnlockableAccount();

    const response = await request(app)
      .get('/api/v1/crypto/unlock')
      .set('Cookie', `pm_session=${token}`);

    expect(response.status).toBe(200);

    expect(response.body.protocolVersion).toBe(1);

    expect(response.body.cryptoProfileId).toBe(cryptoProfileId);

    expect(response.body.kdf).toEqual({
      algorithm: 'ARGON2ID',
      profileVersion: 1,
      memoryKib: 19 * 1024,
      iterations: 2,
      parallelism: 1,

      salt: Buffer.alloc(16, 0x11).toString('base64url'),
    });

    expect(response.body.rootKey).toEqual({
      keyVersion: 1,
      envelopeVersion: 1,

      envelope: Buffer.alloc(61, 0x22).toString('base64url'),

      aad: `pm:v1:ark:crypto-profile:${cryptoProfileId}:key-version:1`,
    });

    expect(response.body.vault).toEqual({
      id: vaultId,
      kind: 'PERSONAL',

      keyVersion: 1,
      rootKeyVersion: 1,
      envelopeVersion: 1,

      envelope: Buffer.alloc(61, 0x33).toString('base64url'),

      aad: `pm:v1:pvk:vault:${vaultId}:key-version:1`,
    });
  });

  it('does not expose recovery or plaintext key material', async () => {
    const { token } = await createUnlockableAccount();

    const response = await request(app)
      .get('/api/v1/crypto/unlock')
      .set('Cookie', `pm_session=${token}`);

    expect(response.status).toBe(200);

    const serialized = JSON.stringify(response.body);

    expect(serialized).not.toContain('recoveryKey');

    expect(serialized).not.toContain('masterPassword');

    expect(serialized).not.toContain('accountSecret');

    expect(serialized).not.toContain('mKEK');

    expect(serialized).not.toContain('plaintext');
  });

  it('requires an authenticated session', async () => {
    const response = await request(app).get('/api/v1/crypto/unlock');

    expect(response.status).toBe(401);

    expect(response.body.error.code).toBe('AUTHENTICATION_REQUIRED');
  });

  it('fails closed when crypto state is incomplete', async () => {
    const user = await prisma.user.create({
      data: {
        email: 'broken@example.com',

        normalizedEmail: 'broken@example.com',

        status: 'ACTIVE',

        emailVerifiedAt: new Date(),

        webauthnUserId: 'broken-webauthn-user',
      },
    });

    const token = generateSecurityToken();

    const now = new Date();

    await prisma.session.create({
      data: {
        userId: user.id,

        tokenHash: Uint8Array.from(hashSecurityToken(token)),

        idleExpiresAt: new Date(now.getTime() + SESSION_IDLE_TTL_MS),

        absoluteExpiresAt: new Date(now.getTime() + SESSION_ABSOLUTE_TTL_MS),
      },
    });

    const response = await request(app)
      .get('/api/v1/crypto/unlock')
      .set('Cookie', `pm_session=${token}`);

    expect(response.status).toBe(409);

    expect(response.body.error.code).toBe('CRYPTO_STATE_INVALID');
  });
});
