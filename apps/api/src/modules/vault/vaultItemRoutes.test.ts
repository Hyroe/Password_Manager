import { randomUUID } from 'node:crypto';

import request from 'supertest';

import { afterAll, beforeEach, describe, expect, it } from 'vitest';

import { createApp } from '../../app.js';

import { SESSION_ABSOLUTE_TTL_MS, SESSION_IDLE_TTL_MS } from '../../config/session.js';

import { encodeBase64Url } from '../../lib/base64Url.js';

import { prisma } from '../../lib/prisma.js';

import { generateSecurityToken, hashSecurityToken } from '../../lib/securityTokens.js';

const app = createApp();

function encryptedFixture(length: number, fill: number, version = 1): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(length).fill(fill);

  bytes[0] = version;

  return bytes;
}

describe('encrypted vault item routes', () => {
  beforeEach(async () => {
    await prisma.itemKeyEnvelope.deleteMany();
    await prisma.vaultItemRevision.deleteMany();
    await prisma.vaultItem.deleteMany();

    await prisma.vaultKeyEnvelope.deleteMany();
    await prisma.vault.deleteMany();

    await prisma.recoveryEnvelope.deleteMany();
    await prisma.rootKeyEnvelope.deleteMany();
    await prisma.userCryptoProfile.deleteMany();

    await prisma.session.deleteMany();
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

  async function createAuthenticatedVault() {
    const user = await prisma.user.create({
      data: {
        email: 'item-api@example.com',

        normalizedEmail: 'item-api@example.com',

        status: 'ACTIVE',

        emailVerifiedAt: new Date(),

        webauthnUserId: 'item-api-webauthn',
      },
    });

    const vaultId = randomUUID();

    const vault = await prisma.vault.create({
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

        encryptedKey: encryptedFixture(61, 0x11),
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
      vault,
      token,
    };
  }

  it('reserves an item and returns deterministic crypto context', async () => {
    const { vault, token } = await createAuthenticatedVault();

    const response = await request(app)
      .post(`/api/v1/vaults/${vault.id}/items/options`)
      .set('Cookie', `pm_session=${token}`)
      .send({});

    expect(response.status).toBe(201);

    expect(response.body).toMatchObject({
      vaultId: vault.id,

      revisionNumber: 1,

      payloadVersion: 1,
      ciphertextVersion: 1,

      itemKeyVersion: 1,
      vaultKeyVersion: 1,

      envelopeVersion: 1,
    });

    expect(response.body.itemId).toBeTypeOf('string');

    expect(response.body.aad.itemKey).toBe(
      `pm:v1:item-key:vault:${vault.id}:item:${response.body.itemId}:revision:1:vault-key-version:1`,
    );

    expect(response.body.aad.payload).toBe(
      `pm:v1:item-payload:vault:${vault.id}:item:${response.body.itemId}:revision:1:item-key-version:1`,
    );

    const storedItem = await prisma.vaultItem.findUnique({
      where: {
        id: response.body.itemId,
      },
    });

    expect(storedItem).not.toBeNull();

    expect(storedItem?.currentRevisionNumber).toBe(0);
  });

  it('stores encrypted item material and consumes the reservation', async () => {
    const { vault, token } = await createAuthenticatedVault();

    const reservation = await request(app)
      .post(`/api/v1/vaults/${vault.id}/items/options`)
      .set('Cookie', `pm_session=${token}`)
      .send({});

    const itemKeyEnvelope = encryptedFixture(61, 0x22);

    const ciphertext = encryptedFixture(128, 0x33);

    const response = await request(app)
      .post(`/api/v1/vaults/${vault.id}/items`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        itemId: reservation.body.itemId,

        revisionNumber: 1,

        payloadVersion: 1,
        ciphertextVersion: 1,

        itemKeyVersion: 1,
        vaultKeyVersion: 1,

        envelopeVersion: 1,

        itemKeyEnvelope: encodeBase64Url(itemKeyEnvelope),

        ciphertext: encodeBase64Url(ciphertext),
      });

    expect(response.status).toBe(201);

    expect(response.body).toMatchObject({
      id: reservation.body.itemId,

      vaultId: vault.id,

      revisionNumber: 1,
    });

    const item = await prisma.vaultItem.findUniqueOrThrow({
      where: {
        id: reservation.body.itemId,
      },
    });

    expect(item.currentRevisionNumber).toBe(1);

    const revision = await prisma.vaultItemRevision.findUniqueOrThrow({
      where: {
        itemId_revisionNumber: {
          itemId: item.id,
          revisionNumber: 1,
        },
      },
    });

    expect(Array.from(revision.ciphertext)).toEqual(Array.from(ciphertext));

    const envelope = await prisma.itemKeyEnvelope.findFirstOrThrow({
      where: {
        revisionId: revision.id,
      },
    });

    expect(Array.from(envelope.encryptedKey)).toEqual(Array.from(itemKeyEnvelope));
  });

  it('rejects replay of an already consumed reservation', async () => {
    const { vault, token } = await createAuthenticatedVault();

    const reservation = await request(app)
      .post(`/api/v1/vaults/${vault.id}/items/options`)
      .set('Cookie', `pm_session=${token}`)
      .send({});

    const itemKeyEnvelope = encryptedFixture(61, 0x44);

    const ciphertext = encryptedFixture(64, 0x55);

    const body = {
      itemId: reservation.body.itemId,

      revisionNumber: 1,

      payloadVersion: 1,
      ciphertextVersion: 1,

      itemKeyVersion: 1,
      vaultKeyVersion: 1,

      envelopeVersion: 1,

      itemKeyEnvelope: encodeBase64Url(itemKeyEnvelope),

      ciphertext: encodeBase64Url(ciphertext),
    };

    const first = await request(app)
      .post(`/api/v1/vaults/${vault.id}/items`)
      .set('Cookie', `pm_session=${token}`)
      .send(body);

    expect(first.status).toBe(201);

    const replay = await request(app)
      .post(`/api/v1/vaults/${vault.id}/items`)
      .set('Cookie', `pm_session=${token}`)
      .send(body);

    expect(replay.status).toBe(409);

    expect(replay.body.error.code).toBe('ITEM_REVISION_CONFLICT');

    expect(
      await prisma.vaultItemRevision.count({
        where: {
          itemId: reservation.body.itemId,
        },
      }),
    ).toBe(1);
  });

  it('rejects crypto material whose embedded version does not match metadata', async () => {
    const { vault, token } = await createAuthenticatedVault();

    const reservation = await request(app)
      .post(`/api/v1/vaults/${vault.id}/items/options`)
      .set('Cookie', `pm_session=${token}`)
      .send({});

    /*
     * Metadata says envelope version 1,
     * but the envelope itself starts with 2.
     */
    const itemKeyEnvelope = encryptedFixture(61, 0x22, 2);

    const ciphertext = encryptedFixture(64, 0x33, 1);

    const response = await request(app)
      .post(`/api/v1/vaults/${vault.id}/items`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        itemId: reservation.body.itemId,

        revisionNumber: 1,

        payloadVersion: 1,
        ciphertextVersion: 1,

        itemKeyVersion: 1,
        vaultKeyVersion: 1,

        envelopeVersion: 1,

        itemKeyEnvelope: encodeBase64Url(itemKeyEnvelope),

        ciphertext: encodeBase64Url(ciphertext),
      });

    expect(response.status).toBe(400);

    expect(response.body.error.code).toBe('INVALID_CRYPTO_MATERIAL');

    const item = await prisma.vaultItem.findUniqueOrThrow({
      where: {
        id: reservation.body.itemId,
      },
    });

    expect(item.currentRevisionNumber).toBe(0);

    expect(
      await prisma.vaultItemRevision.count({
        where: {
          itemId: item.id,
        },
      }),
    ).toBe(0);
  });

  it('lists only completed encrypted items', async () => {
    const { vault, token } = await createAuthenticatedVault();

    const completedReservation = await request(app)
      .post(`/api/v1/vaults/${vault.id}/items/options`)
      .set('Cookie', `pm_session=${token}`)
      .send({});

    const itemKeyEnvelope = encryptedFixture(61, 0x21);

    const ciphertext = encryptedFixture(80, 0x31);

    await request(app)
      .post(`/api/v1/vaults/${vault.id}/items`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        itemId: completedReservation.body.itemId,

        revisionNumber: 1,

        payloadVersion: 1,
        ciphertextVersion: 1,

        itemKeyVersion: 1,
        vaultKeyVersion: 1,

        envelopeVersion: 1,

        itemKeyEnvelope: encodeBase64Url(itemKeyEnvelope),

        ciphertext: encodeBase64Url(ciphertext),
      });

    /*
     * Intentionally abandoned reservation.
     * It must not appear in the list.
     */
    await request(app)
      .post(`/api/v1/vaults/${vault.id}/items/options`)
      .set('Cookie', `pm_session=${token}`)
      .send({});

    const response = await request(app)
      .get(`/api/v1/vaults/${vault.id}/items`)
      .set('Cookie', `pm_session=${token}`);

    expect(response.status).toBe(200);

    expect(response.body.items).toHaveLength(1);

    const [item] = response.body.items;

    expect(item).toMatchObject({
      id: completedReservation.body.itemId,

      vaultId: vault.id,

      revisionNumber: 1,

      payloadVersion: 1,
      ciphertextVersion: 1,

      itemKeyVersion: 1,
      vaultKeyVersion: 1,

      envelopeVersion: 1,

      itemKeyEnvelope: encodeBase64Url(itemKeyEnvelope),

      ciphertext: encodeBase64Url(ciphertext),
    });

    expect(item.aad.itemKey).toBe(
      `pm:v1:item-key:vault:${vault.id}:item:${item.id}:revision:1:vault-key-version:1`,
    );

    expect(item.aad.payload).toBe(
      `pm:v1:item-payload:vault:${vault.id}:item:${item.id}:revision:1:item-key-version:1`,
    );
  });

  it('returns one encrypted vault item', async () => {
    const { vault, token } = await createAuthenticatedVault();

    const reservation = await request(app)
      .post(`/api/v1/vaults/${vault.id}/items/options`)
      .set('Cookie', `pm_session=${token}`)
      .send({});

    const itemKeyEnvelope = encryptedFixture(61, 0x41);

    const ciphertext = encryptedFixture(96, 0x51);

    await request(app)
      .post(`/api/v1/vaults/${vault.id}/items`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        itemId: reservation.body.itemId,

        revisionNumber: 1,

        payloadVersion: 1,
        ciphertextVersion: 1,

        itemKeyVersion: 1,
        vaultKeyVersion: 1,

        envelopeVersion: 1,

        itemKeyEnvelope: encodeBase64Url(itemKeyEnvelope),

        ciphertext: encodeBase64Url(ciphertext),
      });

    const response = await request(app)
      .get(`/api/v1/vaults/${vault.id}/items/${reservation.body.itemId}`)
      .set('Cookie', `pm_session=${token}`);

    expect(response.status).toBe(200);

    expect(response.body).toMatchObject({
      id: reservation.body.itemId,

      vaultId: vault.id,

      revisionNumber: 1,

      payloadVersion: 1,
      ciphertextVersion: 1,

      itemKeyVersion: 1,
      vaultKeyVersion: 1,

      envelopeVersion: 1,
    });

    expect(response.body.itemKeyEnvelope).toBe(encodeBase64Url(itemKeyEnvelope));

    expect(response.body.ciphertext).toBe(encodeBase64Url(ciphertext));
  });

  it('returns 404 for an unknown item', async () => {
    const { vault, token } = await createAuthenticatedVault();

    const response = await request(app)
      .get(`/api/v1/vaults/${vault.id}/items/${randomUUID()}`)
      .set('Cookie', `pm_session=${token}`);

    expect(response.status).toBe(404);

    expect(response.body.error.code).toBe('ITEM_NOT_FOUND');
  });

  it('requires authentication to list vault items', async () => {
    const { vault } = await createAuthenticatedVault();

    const response = await request(app).get(`/api/v1/vaults/${vault.id}/items`);

    expect(response.status).toBe(401);
  });
});
