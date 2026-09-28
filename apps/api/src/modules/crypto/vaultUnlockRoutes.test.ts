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

    await prisma.recoveryEnvelope.create({
      data: {
        cryptoProfileId,

        recoveryVersion: 1,
        rootKeyVersion: 1,

        envelopeVersion: 1,

        encryptedKey: new Uint8Array(61).fill(0x44),
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
  it('returns encrypted material required for Master Password recovery', async () => {
    const { token, cryptoProfileId } = await createUnlockableAccount();

    const response = await request(app)
      .get('/api/v1/crypto/recovery')
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
    });

    expect(response.body.recoveryRootKey).toEqual({
      recoveryVersion: 1,

      rootKeyVersion: 1,

      envelopeVersion: 1,

      envelope: Buffer.alloc(61, 0x44).toString('base64url'),

      aad: `pm:v1:recovery-ark:crypto-profile:${cryptoProfileId}:key-version:1`,
    });

    expect(response.body.rootKey).toMatchObject({
      keyVersion: 1,
      envelopeVersion: 1,

      aad: `pm:v1:ark:crypto-profile:${cryptoProfileId}:key-version:1`,
    });

    expect(response.body.rootKey.updatedAt).toBeTypeOf('string');
  });
  it('does not expose secrets or the current Master Password root envelope during recovery', async () => {
    const { token } = await createUnlockableAccount();

    const response = await request(app)
      .get('/api/v1/crypto/recovery')
      .set('Cookie', `pm_session=${token}`);

    expect(response.status).toBe(200);

    /*
     * Recovery generates a new KDF salt locally,
     * so the current salt is unnecessary.
     */
    expect(response.body.kdf).not.toHaveProperty('salt');

    /*
     * Recovery uses the RecoveryEnvelope to obtain
     * the ARK. The existing Master Password envelope
     * does not need to leave the server.
     */
    expect(response.body.rootKey).not.toHaveProperty('envelope');

    const serialized = JSON.stringify(response.body);

    expect(serialized).not.toContain('accountSecret');

    expect(serialized).not.toContain('recoveryKey');

    expect(serialized).not.toContain('masterPassword');

    expect(serialized).not.toContain('plaintext');
  });
  it('requires an authenticated session for Master Password recovery', async () => {
    const response = await request(app).get('/api/v1/crypto/recovery');

    expect(response.status).toBe(401);

    expect(response.body.error.code).toBe('AUTHENTICATION_REQUIRED');
  });
  it('fails closed when the recovery envelope is missing', async () => {
    const { token, cryptoProfileId } = await createUnlockableAccount();

    await prisma.recoveryEnvelope.deleteMany({
      where: {
        cryptoProfileId,
      },
    });

    const response = await request(app)
      .get('/api/v1/crypto/recovery')
      .set('Cookie', `pm_session=${token}`);

    expect(response.status).toBe(409);

    expect(response.body.error.code).toBe('CRYPTO_STATE_INVALID');
  });
  it('returns the recovery envelope for the current root key version', async () => {
    const { token, cryptoProfileId } = await createUnlockableAccount();

    /*
     * Simulate a later ARK version.
     */
    await prisma.rootKeyEnvelope.create({
      data: {
        cryptoProfileId,

        keyVersion: 2,

        envelopeVersion: 1,

        encryptedKey: new Uint8Array(61).fill(0x55),
      },
    });

    await prisma.recoveryEnvelope.create({
      data: {
        cryptoProfileId,

        recoveryVersion: 2,

        rootKeyVersion: 2,

        envelopeVersion: 1,

        encryptedKey: new Uint8Array(61).fill(0x66),
      },
    });

    const response = await request(app)
      .get('/api/v1/crypto/recovery')
      .set('Cookie', `pm_session=${token}`);

    expect(response.status).toBe(200);

    /*
     * Root key context now includes updatedAt,
     * which is used as the optimistic concurrency
     * token when recovery is completed.
     */
    expect(response.body.rootKey).toMatchObject({
      keyVersion: 2,

      envelopeVersion: 1,

      aad: `pm:v1:ark:crypto-profile:${cryptoProfileId}:key-version:2`,
    });

    expect(response.body.rootKey.updatedAt).toBeTypeOf('string');

    expect(Number.isNaN(Date.parse(response.body.rootKey.updatedAt))).toBe(false);

    expect(response.body.recoveryRootKey).toEqual({
      recoveryVersion: 2,

      rootKeyVersion: 2,

      envelopeVersion: 1,

      envelope: Buffer.alloc(61, 0x66).toString('base64url'),

      aad: `pm:v1:recovery-ark:crypto-profile:${cryptoProfileId}:key-version:2`,
    });
  });
  it('completes Master Password recovery without rotating ARK-dependent envelopes', async () => {
    const { user, token, cryptoProfileId, vaultId } = await createUnlockableAccount();

    /*
     * Obtain the recovery context that the client
     * would use to perform recovery locally.
     */
    const recoveryContext = await request(app)
      .get('/api/v1/crypto/recovery')
      .set('Cookie', `pm_session=${token}`);

    expect(recoveryContext.status).toBe(200);

    expect(recoveryContext.body.rootKey.updatedAt).toBeTypeOf('string');

    const rootBefore = await prisma.rootKeyEnvelope.findFirstOrThrow({
      where: {
        cryptoProfileId,

        keyVersion: recoveryContext.body.rootKey.keyVersion,
      },
    });

    const recoveryBefore = await prisma.recoveryEnvelope.findFirstOrThrow({
      where: {
        cryptoProfileId,

        recoveryVersion: recoveryContext.body.recoveryRootKey.recoveryVersion,
      },
    });

    const vaultBefore = await prisma.vaultKeyEnvelope.findFirstOrThrow({
      where: {
        vaultId,
      },
    });

    const newKdfSalt = Buffer.alloc(16, 0x77);

    /*
     * Serialized envelope:
     *
     * byte 0 = envelope version
     * remaining bytes are opaque encrypted material.
     */
    const newRootEnvelope = Buffer.alloc(61, 0x88);

    newRootEnvelope[0] = 1;

    const response = await request(app)
      .post('/api/v1/crypto/recovery/complete')
      .set('Cookie', `pm_session=${token}`)
      .send({
        protocolVersion: 1,

        kdf: {
          algorithm: 'ARGON2ID',

          profileVersion: 1,

          memoryKib: 19 * 1024,

          iterations: 2,

          parallelism: 1,

          salt: newKdfSalt.toString('base64url'),
        },

        rootKey: {
          keyVersion: recoveryContext.body.rootKey.keyVersion,

          envelopeVersion: 1,

          expectedUpdatedAt: recoveryContext.body.rootKey.updatedAt,

          envelope: newRootEnvelope.toString('base64url'),
        },

        recovery: {
          recoveryVersion: recoveryContext.body.recoveryRootKey.recoveryVersion,

          rootKeyVersion: recoveryContext.body.recoveryRootKey.rootKeyVersion,
        },
      });

    expect(response.status).toBe(204);

    /*
     * KDF salt must have changed.
     */
    const profileAfter = await prisma.userCryptoProfile.findUniqueOrThrow({
      where: {
        id: cryptoProfileId,
      },
    });

    expect(Array.from(profileAfter.kdfSalt)).toEqual(Array.from(newKdfSalt));

    /*
     * The existing RootKeyEnvelope row is updated.
     *
     * Recovery does not rotate the ARK version.
     */
    const rootAfter = await prisma.rootKeyEnvelope.findFirstOrThrow({
      where: {
        cryptoProfileId,

        keyVersion: recoveryContext.body.rootKey.keyVersion,
      },
    });

    expect(rootAfter.id).toBe(rootBefore.id);

    expect(rootAfter.keyVersion).toBe(rootBefore.keyVersion);

    expect(Array.from(rootAfter.encryptedKey)).toEqual(Array.from(newRootEnvelope));

    /*
     * RecoveryEnvelope remains unchanged.
     *
     * It still protects the same ARK with the
     * Recovery Key-derived KEK.
     */
    const recoveryAfter = await prisma.recoveryEnvelope.findUniqueOrThrow({
      where: {
        id: recoveryBefore.id,
      },
    });

    expect(recoveryAfter.recoveryVersion).toBe(recoveryBefore.recoveryVersion);

    expect(recoveryAfter.rootKeyVersion).toBe(recoveryBefore.rootKeyVersion);

    expect(Array.from(recoveryAfter.encryptedKey)).toEqual(Array.from(recoveryBefore.encryptedKey));

    /*
     * VaultKeyEnvelope also remains untouched.
     *
     * Therefore PVK and everything below it in
     * the key hierarchy remain unchanged.
     */
    const vaultAfter = await prisma.vaultKeyEnvelope.findUniqueOrThrow({
      where: {
        id: vaultBefore.id,
      },
    });

    expect(vaultAfter.vaultKeyVersion).toBe(vaultBefore.vaultKeyVersion);

    expect(vaultAfter.rootKeyVersion).toBe(vaultBefore.rootKeyVersion);

    expect(Array.from(vaultAfter.encryptedKey)).toEqual(Array.from(vaultBefore.encryptedKey));

    /*
     * Recovery is a security boundary.
     *
     * Every session belonging to this account
     * must now be revoked.
     */
    const sessions = await prisma.session.findMany({
      where: {
        userId: user.id,
      },
    });

    expect(sessions.length).toBeGreaterThan(0);

    expect(sessions.every((session) => session.revokedAt !== null)).toBe(true);

    /*
     * The current browser cookie must also be
     * explicitly cleared.
     */
    const setCookieHeader = response.headers['set-cookie'];

    expect(setCookieHeader).toBeDefined();

    const cookies = Array.isArray(setCookieHeader)
      ? setCookieHeader.join(';')
      : (setCookieHeader ?? '');

    expect(cookies).toContain('pm_session=');

    expect(cookies).toContain('Expires=Thu, 01 Jan 1970');

    /*
     * The old opaque session token can no longer
     * authenticate even if a client retained it.
     */
    const meAfterRecovery = await request(app)
      .get('/api/v1/me')
      .set('Cookie', `pm_session=${token}`);

    expect(meAfterRecovery.status).toBe(401);

    expect(meAfterRecovery.body.error.code).toBe('AUTHENTICATION_REQUIRED');
  });
  it('requires authentication to complete Master Password recovery', async () => {
    const rootEnvelope = Buffer.alloc(61, 0x88);

    rootEnvelope[0] = 1;

    const response = await request(app)
      .post('/api/v1/crypto/recovery/complete')
      .send({
        protocolVersion: 1,

        kdf: {
          algorithm: 'ARGON2ID',

          profileVersion: 1,

          memoryKib: 19 * 1024,

          iterations: 2,

          parallelism: 1,

          salt: Buffer.alloc(16, 0x77).toString('base64url'),
        },

        rootKey: {
          keyVersion: 1,

          envelopeVersion: 1,

          expectedUpdatedAt: new Date().toISOString(),

          envelope: rootEnvelope.toString('base64url'),
        },

        recovery: {
          recoveryVersion: 1,

          rootKeyVersion: 1,
        },
      });

    expect(response.status).toBe(401);

    expect(response.body.error.code).toBe('AUTHENTICATION_REQUIRED');
  });
  it('rejects recovery material whose embedded envelope version is invalid', async () => {
    const { user, token, cryptoProfileId } = await createUnlockableAccount();

    const recoveryContext = await request(app)
      .get('/api/v1/crypto/recovery')
      .set('Cookie', `pm_session=${token}`);

    expect(recoveryContext.status).toBe(200);

    const profileBefore = await prisma.userCryptoProfile.findUniqueOrThrow({
      where: {
        id: cryptoProfileId,
      },
    });

    const rootBefore = await prisma.rootKeyEnvelope.findFirstOrThrow({
      where: {
        cryptoProfileId,

        keyVersion: recoveryContext.body.rootKey.keyVersion,
      },
    });

    /*
     * Metadata says envelope version 1,
     * but serialized byte 0 says version 2.
     */
    const invalidRootEnvelope = Buffer.alloc(61, 0x88);

    invalidRootEnvelope[0] = 2;

    const response = await request(app)
      .post('/api/v1/crypto/recovery/complete')
      .set('Cookie', `pm_session=${token}`)
      .send({
        protocolVersion: 1,

        kdf: {
          algorithm: 'ARGON2ID',

          profileVersion: 1,

          memoryKib: 19 * 1024,

          iterations: 2,

          parallelism: 1,

          salt: Buffer.alloc(16, 0x77).toString('base64url'),
        },

        rootKey: {
          keyVersion: recoveryContext.body.rootKey.keyVersion,

          envelopeVersion: 1,

          expectedUpdatedAt: recoveryContext.body.rootKey.updatedAt,

          envelope: invalidRootEnvelope.toString('base64url'),
        },

        recovery: {
          recoveryVersion: recoveryContext.body.recoveryRootKey.recoveryVersion,

          rootKeyVersion: recoveryContext.body.recoveryRootKey.rootKeyVersion,
        },
      });

    expect(response.status).toBe(400);

    expect(response.body.error.code).toBe('INVALID_CRYPTO_MATERIAL');

    /*
     * No partial persistence.
     */
    const profileAfter = await prisma.userCryptoProfile.findUniqueOrThrow({
      where: {
        id: cryptoProfileId,
      },
    });

    expect(Array.from(profileAfter.kdfSalt)).toEqual(Array.from(profileBefore.kdfSalt));

    const rootAfter = await prisma.rootKeyEnvelope.findUniqueOrThrow({
      where: {
        id: rootBefore.id,
      },
    });

    expect(Array.from(rootAfter.encryptedKey)).toEqual(Array.from(rootBefore.encryptedKey));

    /*
     * Failed recovery must not revoke sessions.
     */
    const sessions = await prisma.session.findMany({
      where: {
        userId: user.id,
      },
    });

    expect(sessions.length).toBeGreaterThan(0);

    expect(sessions.every((session) => session.revokedAt === null)).toBe(true);
  });
  it('rejects a stale recovery context when the root envelope changed', async () => {
    const { user, token, cryptoProfileId } = await createUnlockableAccount();

    /*
     * Client A obtains the recovery context.
     */
    const recoveryContext = await request(app)
      .get('/api/v1/crypto/recovery')
      .set('Cookie', `pm_session=${token}`);

    expect(recoveryContext.status).toBe(200);

    const staleUpdatedAt = recoveryContext.body.rootKey.updatedAt;

    expect(staleUpdatedAt).toBeTypeOf('string');

    const profileBefore = await prisma.userCryptoProfile.findUniqueOrThrow({
      where: {
        id: cryptoProfileId,
      },
    });

    const currentRoot = await prisma.rootKeyEnvelope.findFirstOrThrow({
      where: {
        cryptoProfileId,

        keyVersion: recoveryContext.body.rootKey.keyVersion,
      },
    });

    /*
     * Simulate another recovery changing the
     * current RootKeyEnvelope after Client A
     * obtained its context.
     *
     * Explicitly advance updatedAt so this test
     * does not depend on millisecond clock timing.
     */
    const replacementEnvelope = Buffer.alloc(61, 0x66);

    replacementEnvelope[0] = 1;

    const replacementUpdatedAt = new Date(new Date(staleUpdatedAt).getTime() + 1000);

    await prisma.rootKeyEnvelope.update({
      where: {
        id: currentRoot.id,
      },

      data: {
        encryptedKey: replacementEnvelope,

        updatedAt: replacementUpdatedAt,
      },
    });

    const proposedEnvelope = Buffer.alloc(61, 0x99);

    proposedEnvelope[0] = 1;

    /*
     * Client A now attempts recovery using the
     * stale expectedUpdatedAt value.
     */
    const response = await request(app)
      .post('/api/v1/crypto/recovery/complete')
      .set('Cookie', `pm_session=${token}`)
      .send({
        protocolVersion: 1,

        kdf: {
          algorithm: 'ARGON2ID',

          profileVersion: 1,

          memoryKib: 19 * 1024,

          iterations: 2,

          parallelism: 1,

          salt: Buffer.alloc(16, 0x77).toString('base64url'),
        },

        rootKey: {
          keyVersion: recoveryContext.body.rootKey.keyVersion,

          envelopeVersion: 1,

          expectedUpdatedAt: staleUpdatedAt,

          envelope: proposedEnvelope.toString('base64url'),
        },

        recovery: {
          recoveryVersion: recoveryContext.body.recoveryRootKey.recoveryVersion,

          rootKeyVersion: recoveryContext.body.recoveryRootKey.rootKeyVersion,
        },
      });

    expect(response.status).toBe(409);

    expect(response.body.error.code).toBe('RECOVERY_CONFLICT');

    /*
     * The winner's RootKeyEnvelope must remain
     * intact. The stale request cannot overwrite it.
     */
    const rootAfter = await prisma.rootKeyEnvelope.findUniqueOrThrow({
      where: {
        id: currentRoot.id,
      },
    });

    expect(Array.from(rootAfter.encryptedKey)).toEqual(Array.from(replacementEnvelope));

    /*
     * The stale request must not partially change
     * the KDF configuration either.
     */
    const profileAfter = await prisma.userCryptoProfile.findUniqueOrThrow({
      where: {
        id: cryptoProfileId,
      },
    });

    expect(Array.from(profileAfter.kdfSalt)).toEqual(Array.from(profileBefore.kdfSalt));

    /*
     * A failed stale recovery is not a successful
     * security transition, so it must not revoke
     * the authenticated session.
     */
    const sessions = await prisma.session.findMany({
      where: {
        userId: user.id,
      },
    });

    expect(sessions.every((session) => session.revokedAt === null)).toBe(true);
  });
});
