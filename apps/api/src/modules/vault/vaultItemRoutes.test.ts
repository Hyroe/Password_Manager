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

  async function createCompletedItem(vaultId: string, token: string) {
    const reservation = await request(app)
      .post(`/api/v1/vaults/${vaultId}/items/options`)
      .set('Cookie', `pm_session=${token}`)
      .send({});

    const itemKeyEnvelope = encryptedFixture(61, 0x61);

    const ciphertext = encryptedFixture(96, 0x71);

    const created = await request(app)
      .post(`/api/v1/vaults/${vaultId}/items`)
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

    expect(created.status).toBe(201);

    return {
      itemId: reservation.body.itemId,

      firstCiphertext: ciphertext,

      firstEnvelope: itemKeyEnvelope,
    };
  }

  async function createAuthenticatedVault(suffix = randomUUID()) {
    const email = `item-api-${suffix}@example.com`;
    const user = await prisma.user.create({
      data: {
        email: email,

        normalizedEmail: email,

        status: 'ACTIVE',

        emailVerifiedAt: new Date(),

        webauthnUserId: `item-api-webauthn-${suffix}`,
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

  it('returns crypto context for the next immutable revision', async () => {
    const { vault, token } = await createAuthenticatedVault();

    const { itemId } = await createCompletedItem(vault.id, token);

    const response = await request(app)
      .post(`/api/v1/vaults/${vault.id}/items/${itemId}/revisions/options`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        expectedRevisionNumber: 1,
      });

    expect(response.status).toBe(200);

    expect(response.body).toMatchObject({
      vaultId: vault.id,
      itemId,

      expectedRevisionNumber: 1,
      revisionNumber: 2,

      payloadVersion: 1,
      ciphertextVersion: 1,

      itemKeyVersion: 1,
      vaultKeyVersion: 1,

      envelopeVersion: 1,
    });

    expect(response.body.aad.itemKey).toBe(
      `pm:v1:item-key:vault:${vault.id}:item:${itemId}:revision:2:vault-key-version:1`,
    );

    expect(response.body.aad.payload).toBe(
      `pm:v1:item-payload:vault:${vault.id}:item:${itemId}:revision:2:item-key-version:1`,
    );
  });

  it('creates a new immutable item revision', async () => {
    const { vault, token } = await createAuthenticatedVault();

    const { itemId, firstCiphertext, firstEnvelope } = await createCompletedItem(vault.id, token);

    const options = await request(app)
      .post(`/api/v1/vaults/${vault.id}/items/${itemId}/revisions/options`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        expectedRevisionNumber: 1,
      });

    const secondEnvelope = encryptedFixture(61, 0x81);

    const secondCiphertext = encryptedFixture(112, 0x91);

    const response = await request(app)
      .post(`/api/v1/vaults/${vault.id}/items/${itemId}/revisions`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        expectedRevisionNumber: 1,

        revisionNumber: options.body.revisionNumber,

        payloadVersion: 1,
        ciphertextVersion: 1,

        itemKeyVersion: 1,
        vaultKeyVersion: 1,

        envelopeVersion: 1,

        itemKeyEnvelope: encodeBase64Url(secondEnvelope),

        ciphertext: encodeBase64Url(secondCiphertext),
      });

    expect(response.status).toBe(201);

    expect(response.body.revisionNumber).toBe(2);

    const item = await prisma.vaultItem.findUniqueOrThrow({
      where: {
        id: itemId,
      },
    });

    expect(item.currentRevisionNumber).toBe(2);

    const revisions = await prisma.vaultItemRevision.findMany({
      where: {
        itemId,
      },

      orderBy: {
        revisionNumber: 'asc',
      },
    });

    expect(revisions).toHaveLength(2);

    /*
     * Revision 1 remains untouched.
     */
    expect(Array.from(revisions[0].ciphertext)).toEqual(Array.from(firstCiphertext));

    expect(Array.from(revisions[1].ciphertext)).toEqual(Array.from(secondCiphertext));

    const firstRevisionEnvelope = await prisma.itemKeyEnvelope.findFirstOrThrow({
      where: {
        revisionId: revisions[0].id,
      },
    });

    expect(Array.from(firstRevisionEnvelope.encryptedKey)).toEqual(Array.from(firstEnvelope));
  });

  it('rejects a stale concurrent item update', async () => {
    const { vault, token } = await createAuthenticatedVault();

    const { itemId } = await createCompletedItem(vault.id, token);

    /*
     * Both clients read revision 1.
     */
    const firstOptions = await request(app)
      .post(`/api/v1/vaults/${vault.id}/items/${itemId}/revisions/options`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        expectedRevisionNumber: 1,
      });

    const secondOptions = await request(app)
      .post(`/api/v1/vaults/${vault.id}/items/${itemId}/revisions/options`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        expectedRevisionNumber: 1,
      });

    expect(firstOptions.status).toBe(200);
    expect(secondOptions.status).toBe(200);

    const firstUpdate = await request(app)
      .post(`/api/v1/vaults/${vault.id}/items/${itemId}/revisions`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        expectedRevisionNumber: 1,
        revisionNumber: 2,

        payloadVersion: 1,
        ciphertextVersion: 1,

        itemKeyVersion: 1,
        vaultKeyVersion: 1,

        envelopeVersion: 1,

        itemKeyEnvelope: encodeBase64Url(encryptedFixture(61, 0xa1)),

        ciphertext: encodeBase64Url(encryptedFixture(100, 0xb1)),
      });

    expect(firstUpdate.status).toBe(201);

    const staleUpdate = await request(app)
      .post(`/api/v1/vaults/${vault.id}/items/${itemId}/revisions`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        expectedRevisionNumber: 1,
        revisionNumber: 2,

        payloadVersion: 1,
        ciphertextVersion: 1,

        itemKeyVersion: 1,
        vaultKeyVersion: 1,

        envelopeVersion: 1,

        itemKeyEnvelope: encodeBase64Url(encryptedFixture(61, 0xc1)),

        ciphertext: encodeBase64Url(encryptedFixture(100, 0xd1)),
      });

    expect(staleUpdate.status).toBe(409);

    expect(staleUpdate.body.error.code).toBe('ITEM_REVISION_CONFLICT');

    expect(
      await prisma.vaultItemRevision.count({
        where: {
          itemId,
        },
      }),
    ).toBe(2);
  });

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

  it('soft deletes an item without destroying encrypted history', async () => {
    const { vault, token } = await createAuthenticatedVault();

    const { itemId } = await createCompletedItem(vault.id, token);

    const revisionBefore = await prisma.vaultItemRevision.findUniqueOrThrow({
      where: {
        itemId_revisionNumber: {
          itemId,
          revisionNumber: 1,
        },
      },
    });

    const envelopeBefore = await prisma.itemKeyEnvelope.findFirstOrThrow({
      where: {
        revisionId: revisionBefore.id,
      },
    });

    const response = await request(app)
      .delete(`/api/v1/vaults/${vault.id}/items/${itemId}`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        expectedRevisionNumber: 1,
      });

    expect(response.status).toBe(200);

    expect(response.body).toMatchObject({
      id: itemId,
      vaultId: vault.id,
      revisionNumber: 1,
    });

    expect(response.body.deletedAt).toBeTypeOf('string');

    const item = await prisma.vaultItem.findUniqueOrThrow({
      where: {
        id: itemId,
      },
    });

    expect(item.deletedAt).not.toBeNull();

    /*
     * Content revision does not change merely
     * because lifecycle state changed.
     */
    expect(item.currentRevisionNumber).toBe(1);

    /*
     * Encrypted history remains intact.
     */
    const revisionAfter = await prisma.vaultItemRevision.findUniqueOrThrow({
      where: {
        id: revisionBefore.id,
      },
    });

    expect(Array.from(revisionAfter.ciphertext)).toEqual(Array.from(revisionBefore.ciphertext));

    const envelopeAfter = await prisma.itemKeyEnvelope.findUniqueOrThrow({
      where: {
        id: envelopeBefore.id,
      },
    });

    expect(Array.from(envelopeAfter.encryptedKey)).toEqual(Array.from(envelopeBefore.encryptedKey));
  });

  it('hides a soft deleted item from normal list and detail routes', async () => {
    const { vault, token } = await createAuthenticatedVault();

    const { itemId } = await createCompletedItem(vault.id, token);

    const deleted = await request(app)
      .delete(`/api/v1/vaults/${vault.id}/items/${itemId}`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        expectedRevisionNumber: 1,
      });

    expect(deleted.status).toBe(200);

    const listResponse = await request(app)
      .get(`/api/v1/vaults/${vault.id}/items`)
      .set('Cookie', `pm_session=${token}`);

    expect(listResponse.status).toBe(200);

    expect(listResponse.body.items).toHaveLength(0);

    const detailResponse = await request(app)
      .get(`/api/v1/vaults/${vault.id}/items/${itemId}`)
      .set('Cookie', `pm_session=${token}`);

    expect(detailResponse.status).toBe(404);

    expect(detailResponse.body.error.code).toBe('ITEM_NOT_FOUND');

    /*
     * Physical records still exist.
     */
    expect(
      await prisma.vaultItemRevision.count({
        where: {
          itemId,
        },
      }),
    ).toBe(1);
  });

  it('allows an idempotent retry of the same delete', async () => {
    const { vault, token } = await createAuthenticatedVault();

    const { itemId } = await createCompletedItem(vault.id, token);

    const first = await request(app)
      .delete(`/api/v1/vaults/${vault.id}/items/${itemId}`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        expectedRevisionNumber: 1,
      });

    expect(first.status).toBe(200);

    const second = await request(app)
      .delete(`/api/v1/vaults/${vault.id}/items/${itemId}`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        expectedRevisionNumber: 1,
      });

    expect(second.status).toBe(200);

    expect(second.body.deletedAt).toBe(first.body.deletedAt);

    expect(
      await prisma.vaultItemRevision.count({
        where: {
          itemId,
        },
      }),
    ).toBe(1);
  });

  it('rejects a stale delete after the item was updated', async () => {
    const { vault, token } = await createAuthenticatedVault();

    const { itemId } = await createCompletedItem(vault.id, token);

    /*
     * Client A currently knows revision 1.
     *
     * Client B now creates revision 2.
     */
    const options = await request(app)
      .post(`/api/v1/vaults/${vault.id}/items/${itemId}/revisions/options`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        expectedRevisionNumber: 1,
      });

    expect(options.status).toBe(200);

    const update = await request(app)
      .post(`/api/v1/vaults/${vault.id}/items/${itemId}/revisions`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        expectedRevisionNumber: 1,
        revisionNumber: 2,

        payloadVersion: 1,
        ciphertextVersion: 1,

        itemKeyVersion: 1,
        vaultKeyVersion: 1,

        envelopeVersion: 1,

        itemKeyEnvelope: encodeBase64Url(encryptedFixture(61, 0xa2)),

        ciphertext: encodeBase64Url(encryptedFixture(100, 0xb2)),
      });

    expect(update.status).toBe(201);

    /*
     * Client A tries deleting what it thinks
     * is still revision 1.
     */
    const staleDelete = await request(app)
      .delete(`/api/v1/vaults/${vault.id}/items/${itemId}`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        expectedRevisionNumber: 1,
      });

    expect(staleDelete.status).toBe(409);

    expect(staleDelete.body.error.code).toBe('ITEM_REVISION_CONFLICT');

    const item = await prisma.vaultItem.findUniqueOrThrow({
      where: {
        id: itemId,
      },
    });

    expect(item.currentRevisionNumber).toBe(2);

    expect(item.deletedAt).toBeNull();

    expect(
      await prisma.vaultItemRevision.count({
        where: {
          itemId,
        },
      }),
    ).toBe(2);
  });

  it('does not allow another user to delete the item', async () => {
    const first = await createAuthenticatedVault();

    const second = await createAuthenticatedVault();

    const { itemId } = await createCompletedItem(first.vault.id, first.token);

    const response = await request(app)
      .delete(`/api/v1/vaults/${first.vault.id}/items/${itemId}`)
      .set('Cookie', `pm_session=${second.token}`)
      .send({
        expectedRevisionNumber: 1,
      });

    expect(response.status).toBe(404);

    const item = await prisma.vaultItem.findUniqueOrThrow({
      where: {
        id: itemId,
      },
    });

    expect(item.deletedAt).toBeNull();
  });

  it('restores a soft deleted item without creating a new revision', async () => {
    const { vault, token } = await createAuthenticatedVault();

    const { itemId } = await createCompletedItem(vault.id, token);

    const deleted = await request(app)
      .delete(`/api/v1/vaults/${vault.id}/items/${itemId}`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        expectedRevisionNumber: 1,
      });

    expect(deleted.status).toBe(200);

    const restored = await request(app)
      .post(`/api/v1/vaults/${vault.id}/items/${itemId}/restore`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        expectedRevisionNumber: 1,
      });

    expect(restored.status).toBe(200);

    const item = await prisma.vaultItem.findUniqueOrThrow({
      where: {
        id: itemId,
      },
    });

    expect(item.deletedAt).toBeNull();

    expect(item.currentRevisionNumber).toBe(1);

    expect(
      await prisma.vaultItemRevision.count({
        where: {
          itemId,
        },
      }),
    ).toBe(1);
  });

  it('allows an idempotent restore retry', async () => {
    const { vault, token } = await createAuthenticatedVault();

    const { itemId } = await createCompletedItem(vault.id, token);

    await request(app)
      .delete(`/api/v1/vaults/${vault.id}/items/${itemId}`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        expectedRevisionNumber: 1,
      });

    const first = await request(app)
      .post(`/api/v1/vaults/${vault.id}/items/${itemId}/restore`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        expectedRevisionNumber: 1,
      });

    expect(first.status).toBe(200);

    const second = await request(app)
      .post(`/api/v1/vaults/${vault.id}/items/${itemId}/restore`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        expectedRevisionNumber: 1,
      });

    expect(second.status).toBe(200);

    expect(
      await prisma.vaultItemRevision.count({
        where: {
          itemId,
        },
      }),
    ).toBe(1);
  });

  it('includes deleted items only when requested', async () => {
    const { vault, token } = await createAuthenticatedVault();

    const { itemId } = await createCompletedItem(vault.id, token);

    await request(app)
      .delete(`/api/v1/vaults/${vault.id}/items/${itemId}`)
      .set('Cookie', `pm_session=${token}`)
      .send({
        expectedRevisionNumber: 1,
      });

    const normal = await request(app)
      .get(`/api/v1/vaults/${vault.id}/items`)
      .set('Cookie', `pm_session=${token}`);

    expect(normal.body.items).toHaveLength(0);

    const withDeleted = await request(app)
      .get(`/api/v1/vaults/${vault.id}/items?includeDeleted=true`)
      .set('Cookie', `pm_session=${token}`);

    expect(withDeleted.body.items).toHaveLength(1);

    expect(withDeleted.body.items[0].id).toBe(itemId);

    expect(withDeleted.body.items[0].deletedAt).toBeTypeOf('string');
  });
});
