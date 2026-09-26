import { randomUUID } from 'node:crypto';

import request from 'supertest';

import { afterAll, beforeEach, describe, expect, it } from 'vitest';

import { createApp } from '../../app.js';

import { SESSION_ABSOLUTE_TTL_MS, SESSION_IDLE_TTL_MS } from '../../config/session.js';

import { encodeBase64Url } from '../../lib/base64Url.js';

import { prisma } from '../../lib/prisma.js';

import { generateSecurityToken, hashSecurityToken } from '../../lib/securityTokens.js';

const app = createApp();

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

        encryptedKey: new Uint8Array(61).fill(0x11),
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

    const itemKeyEnvelope = new Uint8Array(61).fill(0x22);

    const ciphertext = new Uint8Array(128).fill(0x33);

    ciphertext[0] = 1;

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

    const body = {
      itemId: reservation.body.itemId,

      revisionNumber: 1,

      payloadVersion: 1,
      ciphertextVersion: 1,

      itemKeyVersion: 1,
      vaultKeyVersion: 1,

      envelopeVersion: 1,

      itemKeyEnvelope: encodeBase64Url(new Uint8Array(61).fill(0x44)),

      ciphertext: encodeBase64Url(new Uint8Array(64).fill(0x55)),
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
});
