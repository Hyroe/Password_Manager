import { afterAll, beforeEach, describe, expect, it } from 'vitest';

import { prisma } from '../../lib/prisma.js';
import { randomUUID } from 'node:crypto';

describe('encrypted vault item persistence', () => {
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

  async function createPersonalVault() {
    const user = await prisma.user.create({
      data: {
        email: 'items@example.com',
        normalizedEmail: 'items@example.com',
        status: 'ACTIVE',
        emailVerifiedAt: new Date(),
        webauthnUserId: 'items-webauthn-user',
      },
    });

    const vault = await prisma.vault.create({
      data: {
        id: randomUUID(),
        userId: user.id,
        kind: 'PERSONAL',
      },
    });

    return {
      user,
      vault,
    };
  }

  it('stores only encrypted item revision material', async () => {
    const { vault } = await createPersonalVault();

    const item = await prisma.vaultItem.create({
      data: {
        vaultId: vault.id,
        currentRevisionNumber: 1,
      },
    });

    const ciphertext = new Uint8Array(128).fill(0x22);

    const revision = await prisma.vaultItemRevision.create({
      data: {
        itemId: item.id,

        revisionNumber: 1,

        payloadVersion: 1,
        ciphertextVersion: 1,

        ciphertext,
      },
    });

    const envelope = await prisma.itemKeyEnvelope.create({
      data: {
        revisionId: revision.id,

        itemKeyVersion: 1,
        vaultKeyVersion: 1,

        envelopeVersion: 1,

        encryptedKey: new Uint8Array(61).fill(0x33),
      },
    });

    expect(item.currentRevisionNumber).toBe(1);

    expect(Array.from(revision.ciphertext)).toEqual(Array.from(ciphertext));

    expect(envelope.encryptedKey.length).toBe(61);

    expect(envelope.itemKeyVersion).toBe(1);

    expect(envelope.vaultKeyVersion).toBe(1);
  });

  it('prevents duplicate revision numbers for the same item', async () => {
    const { vault } = await createPersonalVault();

    const item = await prisma.vaultItem.create({
      data: {
        vaultId: vault.id,
      },
    });

    const revisionData = {
      itemId: item.id,

      revisionNumber: 1,

      payloadVersion: 1,
      ciphertextVersion: 1,

      ciphertext: new Uint8Array(64).fill(0x44),
    };

    await prisma.vaultItemRevision.create({
      data: revisionData,
    });

    await expect(
      prisma.vaultItemRevision.create({
        data: revisionData,
      }),
    ).rejects.toThrow();
  });

  it('allows the same item key to be rewrapped for another vault key version', async () => {
    const { vault } = await createPersonalVault();

    const item = await prisma.vaultItem.create({
      data: {
        vaultId: vault.id,
        currentRevisionNumber: 1,
      },
    });

    const revision = await prisma.vaultItemRevision.create({
      data: {
        itemId: item.id,

        revisionNumber: 1,

        payloadVersion: 1,
        ciphertextVersion: 1,

        ciphertext: new Uint8Array(64).fill(0x55),
      },
    });

    await prisma.itemKeyEnvelope.create({
      data: {
        revisionId: revision.id,

        itemKeyVersion: 1,
        vaultKeyVersion: 1,

        envelopeVersion: 1,

        encryptedKey: new Uint8Array(61).fill(0x66),
      },
    });

    await prisma.itemKeyEnvelope.create({
      data: {
        revisionId: revision.id,

        itemKeyVersion: 1,
        vaultKeyVersion: 2,

        envelopeVersion: 1,

        encryptedKey: new Uint8Array(61).fill(0x77),
      },
    });

    const envelopes = await prisma.itemKeyEnvelope.findMany({
      where: {
        revisionId: revision.id,
      },

      orderBy: {
        vaultKeyVersion: 'asc',
      },
    });

    expect(envelopes).toHaveLength(2);

    expect(envelopes.map((entry) => entry.vaultKeyVersion)).toEqual([1, 2]);
  });
});
