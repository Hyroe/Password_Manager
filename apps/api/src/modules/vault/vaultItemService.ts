import { prisma } from '../../lib/prisma.js';
import { encodeBase64Url } from '../../lib/base64Url.js';
import { encodeVaultItemCursor, type VaultItemCursor } from './vaultItemPagination.js';
import { encodeVaultItemSyncCursor, type VaultItemSyncCursor } from './vaultItemSyncCursor.js';
import {
  VAULT_ITEM_RESERVATION_TTL_MS,
  getVaultItemReservationExpiresAt,
  isVaultItemReservationExpired,
} from './vaultItemReservationPolicy.js';

import {
  ITEM_CIPHERTEXT_VERSION,
  ITEM_KEY_ENVELOPE_BYTES,
  ITEM_KEY_ENVELOPE_VERSION,
  ITEM_KEY_VERSION,
  ITEM_PAYLOAD_VERSION,
  MAX_ITEM_CIPHERTEXT_BYTES,
  MIN_ITEM_CIPHERTEXT_BYTES,
  itemKeyAad,
  itemPayloadAad,
} from './vaultItemCryptoPolicy.js';
import { Prisma } from '../../generated/prisma/client.js';

interface CreateEncryptedVaultItemInput {
  itemId: string;

  revisionNumber: number;

  payloadVersion: number;
  ciphertextVersion: number;

  itemKeyVersion: number;
  vaultKeyVersion: number;

  envelopeVersion: number;

  itemKeyEnvelope: Uint8Array<ArrayBuffer>;

  ciphertext: Uint8Array<ArrayBuffer>;
}

export async function reserveVaultItem(userId: string, vaultId: string) {
  return prisma.$transaction(async (tx) => {
    const vault = await tx.vault.findFirst({
      where: {
        id: vaultId,
        userId,
      },
    });

    if (!vault) {
      throw new Error('VAULT_NOT_FOUND');
    }

    /*
     * Opportunistic cleanup.
     *
     * No cron infrastructure is needed
     * yet. Creating a new reservation
     * cleans old abandoned reservations
     * from this vault.
     */
    await cleanupExpiredVaultItemReservations(tx, vaultId);

    const vaultKeyEnvelope = await tx.vaultKeyEnvelope.findFirst({
      where: {
        vaultId,
      },

      orderBy: {
        vaultKeyVersion: 'desc',
      },
    });

    if (!vaultKeyEnvelope) {
      throw new Error('CRYPTO_STATE_INVALID');
    }

    const item = await tx.vaultItem.create({
      data: {
        vaultId,
        currentRevisionNumber: 0,
      },
    });

    const revisionNumber = 1;

    return {
      vaultId,
      itemId: item.id,

      revisionNumber,

      payloadVersion: ITEM_PAYLOAD_VERSION,

      ciphertextVersion: ITEM_CIPHERTEXT_VERSION,

      itemKeyVersion: ITEM_KEY_VERSION,

      vaultKeyVersion: vaultKeyEnvelope.vaultKeyVersion,

      envelopeVersion: ITEM_KEY_ENVELOPE_VERSION,

      expiresAt: getVaultItemReservationExpiresAt(item.createdAt),

      aad: {
        itemKey: itemKeyAad(vaultId, item.id, revisionNumber, vaultKeyEnvelope.vaultKeyVersion),

        payload: itemPayloadAad(vaultId, item.id, revisionNumber, ITEM_KEY_VERSION),
      },
    };
  });
}

export async function createEncryptedVaultItem(
  userId: string,
  vaultId: string,
  input: CreateEncryptedVaultItemInput,
) {
  if (input.itemKeyEnvelope.length !== ITEM_KEY_ENVELOPE_BYTES) {
    throw new Error('INVALID_CRYPTO_MATERIAL');
  }

  if (
    input.ciphertext.length < MIN_ITEM_CIPHERTEXT_BYTES ||
    input.ciphertext.length > MAX_ITEM_CIPHERTEXT_BYTES
  ) {
    throw new Error('INVALID_CRYPTO_MATERIAL');
  }
  if (
    input.itemKeyEnvelope[0] !== input.envelopeVersion ||
    input.ciphertext[0] !== input.ciphertextVersion
  ) {
    throw new Error('INVALID_CRYPTO_MATERIAL');
  }

  const result = await prisma.$transaction(async (tx) => {
    const vault = await tx.vault.findFirst({
      where: {
        id: vaultId,
        userId,
      },
    });

    if (!vault) {
      throw new Error('VAULT_NOT_FOUND');
    }

    const item = await tx.vaultItem.findFirst({
      where: {
        id: input.itemId,
        vaultId,
        deletedAt: null,
      },
    });

    if (!item) {
      throw new Error('ITEM_RESERVATION_NOT_FOUND');
    }

    if (isVaultItemReservationExpired(item.createdAt)) {
      await tx.vaultItem.deleteMany({
        where: {
          id: item.id,
          vaultId,

          currentRevisionNumber: 0,

          deletedAt: null,

          revisions: {
            none: {},
          },
        },
      });

      return {
        expired: true as const,
      };
    }

    if (item.currentRevisionNumber !== 0 || input.revisionNumber !== 1) {
      throw new Error('ITEM_REVISION_CONFLICT');
    }

    const currentVaultKey = await tx.vaultKeyEnvelope.findFirst({
      where: {
        vaultId,
      },

      orderBy: {
        vaultKeyVersion: 'desc',
      },
    });

    if (!currentVaultKey) {
      throw new Error('CRYPTO_STATE_INVALID');
    }

    if (currentVaultKey.vaultKeyVersion !== input.vaultKeyVersion) {
      throw new Error('VAULT_KEY_VERSION_CHANGED');
    }

    const claimed = await tx.vaultItem.updateMany({
      where: {
        id: item.id,
        vaultId,
        currentRevisionNumber: 0,
        deletedAt: null,
      },

      data: {
        currentRevisionNumber: 1,
      },
    });

    if (claimed.count !== 1) {
      throw new Error('ITEM_REVISION_CONFLICT');
    }

    const revision = await tx.vaultItemRevision.create({
      data: {
        itemId: item.id,

        revisionNumber: input.revisionNumber,

        payloadVersion: input.payloadVersion,

        ciphertextVersion: input.ciphertextVersion,

        ciphertext: input.ciphertext,
      },
    });

    await tx.itemKeyEnvelope.create({
      data: {
        revisionId: revision.id,

        itemKeyVersion: input.itemKeyVersion,

        vaultKeyVersion: input.vaultKeyVersion,

        envelopeVersion: input.envelopeVersion,

        encryptedKey: input.itemKeyEnvelope,
      },
    });

    await tx.vaultItemChange.create({
      data: {
        vaultId,
        itemId: item.id,

        revisionNumber: input.revisionNumber,

        kind: 'CREATED',

        deletedAt: null,
      },
    });

    return {
      expired: false as const,

      item: {
        id: item.id,
        vaultId,

        revisionNumber: input.revisionNumber,

        createdAt: revision.createdAt,
      },
    };
  });

  if (result.expired) {
    throw new Error('ITEM_RESERVATION_EXPIRED');
  }

  return result.item;
}

async function getCurrentVaultKeyVersion(vaultId: string): Promise<number> {
  const envelope = await prisma.vaultKeyEnvelope.findFirst({
    where: {
      vaultId,
    },

    orderBy: {
      vaultKeyVersion: 'desc',
    },

    select: {
      vaultKeyVersion: true,
    },
  });

  if (!envelope) {
    throw new Error('CRYPTO_STATE_INVALID');
  }

  return envelope.vaultKeyVersion;
}

async function buildEncryptedItemResponse(
  vaultId: string,
  itemId: string,
  revisionNumber: number,
  vaultKeyVersion: number,
  updatedAt: Date,
) {
  const revision = await prisma.vaultItemRevision.findUnique({
    where: {
      itemId_revisionNumber: {
        itemId,
        revisionNumber,
      },
    },
  });

  if (!revision) {
    throw new Error('CRYPTO_STATE_INVALID');
  }

  const keyEnvelope = await prisma.itemKeyEnvelope.findUnique({
    where: {
      revisionId_vaultKeyVersion: {
        revisionId: revision.id,
        vaultKeyVersion,
      },
    },
  });

  if (!keyEnvelope) {
    throw new Error('CRYPTO_STATE_INVALID');
  }

  return {
    id: itemId,
    vaultId,

    revisionNumber,

    payloadVersion: revision.payloadVersion,

    ciphertextVersion: revision.ciphertextVersion,

    itemKeyVersion: keyEnvelope.itemKeyVersion,

    vaultKeyVersion: keyEnvelope.vaultKeyVersion,

    envelopeVersion: keyEnvelope.envelopeVersion,

    itemKeyEnvelope: encodeBase64Url(keyEnvelope.encryptedKey),

    ciphertext: encodeBase64Url(revision.ciphertext),

    aad: {
      itemKey: itemKeyAad(vaultId, itemId, revisionNumber, keyEnvelope.vaultKeyVersion),

      payload: itemPayloadAad(vaultId, itemId, revisionNumber, keyEnvelope.itemKeyVersion),
    },

    createdAt: revision.createdAt,

    updatedAt,
  };
}

export async function listEncryptedVaultItems(
  userId: string,
  vaultId: string,
  includeDeleted = false,
) {
  const result = await listEncryptedVaultItemsPage(userId, vaultId, {
    includeDeleted,

    /*
     * Legacy/internal convenience.
     * External API is paginated.
     */
    limit: 100,
  });

  return result.items;
}

export async function getEncryptedVaultItem(userId: string, vaultId: string, itemId: string) {
  const item = await prisma.vaultItem.findFirst({
    where: {
      id: itemId,
      vaultId,

      deletedAt: null,

      currentRevisionNumber: {
        gt: 0,
      },

      vault: {
        userId,
      },
    },

    select: {
      id: true,
      currentRevisionNumber: true,
      updatedAt: true,
    },
  });

  if (!item) {
    throw new Error('ITEM_NOT_FOUND');
  }

  const vaultKeyVersion = await getCurrentVaultKeyVersion(vaultId);

  return buildEncryptedItemResponse(
    vaultId,
    item.id,
    item.currentRevisionNumber,
    vaultKeyVersion,
    item.updatedAt,
  );
}

export async function getVaultItemUpdateOptions(
  userId: string,
  vaultId: string,
  itemId: string,
  expectedRevisionNumber: number,
) {
  const item = await prisma.vaultItem.findFirst({
    where: {
      id: itemId,
      vaultId,
      deletedAt: null,

      vault: {
        userId,
      },
    },

    select: {
      id: true,
      currentRevisionNumber: true,
    },
  });

  if (!item) {
    throw new Error('ITEM_NOT_FOUND');
  }

  if (item.currentRevisionNumber !== expectedRevisionNumber) {
    throw new Error('ITEM_REVISION_CONFLICT');
  }

  const vaultKeyEnvelope = await prisma.vaultKeyEnvelope.findFirst({
    where: {
      vaultId,
    },

    orderBy: {
      vaultKeyVersion: 'desc',
    },
  });

  if (!vaultKeyEnvelope) {
    throw new Error('CRYPTO_STATE_INVALID');
  }

  const revisionNumber = expectedRevisionNumber + 1;

  return {
    vaultId,
    itemId,

    expectedRevisionNumber,
    revisionNumber,

    payloadVersion: ITEM_PAYLOAD_VERSION,

    ciphertextVersion: ITEM_CIPHERTEXT_VERSION,

    itemKeyVersion: ITEM_KEY_VERSION,

    vaultKeyVersion: vaultKeyEnvelope.vaultKeyVersion,

    envelopeVersion: ITEM_KEY_ENVELOPE_VERSION,

    aad: {
      itemKey: itemKeyAad(vaultId, itemId, revisionNumber, vaultKeyEnvelope.vaultKeyVersion),

      payload: itemPayloadAad(vaultId, itemId, revisionNumber, ITEM_KEY_VERSION),
    },
  };
}

interface CreateEncryptedVaultItemRevisionInput {
  expectedRevisionNumber: number;

  revisionNumber: number;

  payloadVersion: number;
  ciphertextVersion: number;

  itemKeyVersion: number;
  vaultKeyVersion: number;

  envelopeVersion: number;

  itemKeyEnvelope: Uint8Array<ArrayBuffer>;

  ciphertext: Uint8Array<ArrayBuffer>;
}

export async function createEncryptedVaultItemRevision(
  userId: string,
  vaultId: string,
  itemId: string,
  input: CreateEncryptedVaultItemRevisionInput,
) {
  if (input.itemKeyEnvelope.length !== ITEM_KEY_ENVELOPE_BYTES) {
    throw new Error('INVALID_CRYPTO_MATERIAL');
  }

  if (
    input.ciphertext.length < MIN_ITEM_CIPHERTEXT_BYTES ||
    input.ciphertext.length > MAX_ITEM_CIPHERTEXT_BYTES
  ) {
    throw new Error('INVALID_CRYPTO_MATERIAL');
  }

  if (
    input.itemKeyEnvelope[0] !== input.envelopeVersion ||
    input.ciphertext[0] !== input.ciphertextVersion
  ) {
    throw new Error('INVALID_CRYPTO_MATERIAL');
  }

  if (input.revisionNumber !== input.expectedRevisionNumber + 1) {
    throw new Error('ITEM_REVISION_CONFLICT');
  }

  return prisma.$transaction(async (tx) => {
    const item = await tx.vaultItem.findFirst({
      where: {
        id: itemId,
        vaultId,
        deletedAt: null,

        vault: {
          userId,
        },
      },

      select: {
        id: true,
        currentRevisionNumber: true,
      },
    });

    if (!item) {
      throw new Error('ITEM_NOT_FOUND');
    }

    if (item.currentRevisionNumber !== input.expectedRevisionNumber) {
      throw new Error('ITEM_REVISION_CONFLICT');
    }

    const currentVaultKey = await tx.vaultKeyEnvelope.findFirst({
      where: {
        vaultId,
      },

      orderBy: {
        vaultKeyVersion: 'desc',
      },
    });

    if (!currentVaultKey) {
      throw new Error('CRYPTO_STATE_INVALID');
    }

    if (currentVaultKey.vaultKeyVersion !== input.vaultKeyVersion) {
      throw new Error('VAULT_KEY_VERSION_CHANGED');
    }

    /*
     * Atomic compare-and-set.
     *
     * Only a client whose expected
     * revision is still current can
     * advance the item.
     */
    const claimed = await tx.vaultItem.updateMany({
      where: {
        id: itemId,
        vaultId,

        currentRevisionNumber: input.expectedRevisionNumber,

        deletedAt: null,
      },

      data: {
        currentRevisionNumber: input.revisionNumber,
      },
    });

    if (claimed.count !== 1) {
      throw new Error('ITEM_REVISION_CONFLICT');
    }

    const revision = await tx.vaultItemRevision.create({
      data: {
        itemId,

        revisionNumber: input.revisionNumber,

        payloadVersion: input.payloadVersion,

        ciphertextVersion: input.ciphertextVersion,

        ciphertext: input.ciphertext,
      },
    });

    await tx.itemKeyEnvelope.create({
      data: {
        revisionId: revision.id,

        itemKeyVersion: input.itemKeyVersion,

        vaultKeyVersion: input.vaultKeyVersion,

        envelopeVersion: input.envelopeVersion,

        encryptedKey: input.itemKeyEnvelope,
      },
    });

    await tx.vaultItemChange.create({
      data: {
        vaultId,
        itemId,

        revisionNumber: input.revisionNumber,

        kind: 'UPDATED',

        deletedAt: null,
      },
    });

    return {
      id: item.id,
      vaultId,

      revisionNumber: input.revisionNumber,

      createdAt: revision.createdAt,
    };
  });
}

export async function softDeleteVaultItem(
  userId: string,
  vaultId: string,
  itemId: string,
  expectedRevisionNumber: number,
) {
  return prisma.$transaction(async (tx) => {
    const item = await tx.vaultItem.findFirst({
      where: {
        id: itemId,
        vaultId,

        vault: {
          userId,
        },
      },

      select: {
        id: true,
        currentRevisionNumber: true,
        deletedAt: true,
      },
    });

    if (!item) {
      throw new Error('ITEM_NOT_FOUND');
    }

    /*
     * Revision comparison happens before
     * idempotent delete handling.
     *
     * A stale client must not be able to
     * delete a newer revision.
     */
    if (item.currentRevisionNumber !== expectedRevisionNumber) {
      throw new Error('ITEM_REVISION_CONFLICT');
    }

    /*
     * DELETE is idempotent for the same
     * current revision.
     *
     * Useful when the original response
     * was lost and the client retries.
     */
    if (item.deletedAt) {
      return {
        id: item.id,
        vaultId,

        revisionNumber: item.currentRevisionNumber,

        deletedAt: item.deletedAt,
      };
    }

    const deletedAt = new Date();

    /*
     * Atomic compare-and-set:
     *
     * - item must still be active
     * - revision must still match
     */
    const deleted = await tx.vaultItem.updateMany({
      where: {
        id: itemId,
        vaultId,

        currentRevisionNumber: expectedRevisionNumber,

        deletedAt: null,
      },

      data: {
        deletedAt,
      },
    });

    if (deleted.count !== 1) {
      throw new Error('ITEM_REVISION_CONFLICT');
    }

    await tx.vaultItemChange.create({
      data: {
        vaultId,
        itemId,

        revisionNumber: expectedRevisionNumber,

        kind: 'DELETED',

        deletedAt,
        changedAt: deletedAt,
      },
    });

    return {
      id: item.id,
      vaultId,

      revisionNumber: expectedRevisionNumber,

      deletedAt,
    };
  });
}

export async function restoreVaultItem(
  userId: string,
  vaultId: string,
  itemId: string,
  expectedRevisionNumber: number,
) {
  return prisma.$transaction(async (tx) => {
    const item = await tx.vaultItem.findFirst({
      where: {
        id: itemId,
        vaultId,

        vault: {
          userId,
        },
      },

      select: {
        id: true,
        currentRevisionNumber: true,
        deletedAt: true,
      },
    });

    if (!item) {
      throw new Error('ITEM_NOT_FOUND');
    }

    if (item.currentRevisionNumber !== expectedRevisionNumber) {
      throw new Error('ITEM_REVISION_CONFLICT');
    }

    if (!item.deletedAt) {
      return {
        id: item.id,
        vaultId,

        revisionNumber: item.currentRevisionNumber,

        restoredAt: null,
      };
    }

    const restoredAt = new Date();

    const restored = await tx.vaultItem.updateMany({
      where: {
        id: itemId,
        vaultId,

        currentRevisionNumber: expectedRevisionNumber,

        deletedAt: {
          not: null,
        },
      },

      data: {
        deletedAt: null,
      },
    });

    if (restored.count !== 1) {
      throw new Error('ITEM_REVISION_CONFLICT');
    }

    await tx.vaultItemChange.create({
      data: {
        vaultId,
        itemId,

        revisionNumber: expectedRevisionNumber,

        kind: 'RESTORED',

        deletedAt: null,
        changedAt: restoredAt,
      },
    });

    return {
      id: item.id,
      vaultId,

      revisionNumber: expectedRevisionNumber,

      restoredAt,
    };
  });
}

interface ListEncryptedVaultItemsOptions {
  includeDeleted: boolean;
  limit: number;

  cursor?: VaultItemCursor;
}

export async function listEncryptedVaultItemsPage(
  userId: string,
  vaultId: string,
  options: ListEncryptedVaultItemsOptions,
) {
  const vault = await prisma.vault.findFirst({
    where: {
      id: vaultId,
      userId,
    },

    select: {
      id: true,
    },
  });

  if (!vault) {
    throw new Error('VAULT_NOT_FOUND');
  }

  const vaultKeyVersion = await getCurrentVaultKeyVersion(vaultId);

  const snapshotAt = options.cursor ? new Date(options.cursor.snapshotAt) : new Date();

  /*
   * Fetch one extra row so we can tell
   * whether another page exists.
   */
  const items = await prisma.vaultItem.findMany({
    where: {
      vaultId,

      ...(options.includeDeleted
        ? {}
        : {
            deletedAt: null,
          }),

      currentRevisionNumber: {
        gt: 0,
      },

      /*
       * Freeze the result set to the time
       * the first page was requested.
       */
      updatedAt: {
        lte: snapshotAt,
      },

      ...(options.cursor
        ? {
            OR: [
              {
                updatedAt: {
                  lt: new Date(options.cursor.updatedAt),
                },
              },

              {
                updatedAt: new Date(options.cursor.updatedAt),

                id: {
                  lt: options.cursor.itemId,
                },
              },
            ],
          }
        : {}),
    },

    select: {
      id: true,

      currentRevisionNumber: true,

      deletedAt: true,

      updatedAt: true,
    },

    orderBy: [
      {
        updatedAt: 'desc',
      },

      {
        id: 'desc',
      },
    ],

    take: options.limit + 1,
  });

  const hasMore = items.length > options.limit;

  const pageItems = hasMore ? items.slice(0, options.limit) : items;

  const encryptedItems = await Promise.all(
    pageItems.map(async (item) => {
      const encryptedItem = await buildEncryptedItemResponse(
        vaultId,
        item.id,
        item.currentRevisionNumber,
        vaultKeyVersion,
        item.updatedAt,
      );

      return {
        ...encryptedItem,

        deletedAt: item.deletedAt,
      };
    }),
  );

  const lastItem = pageItems[pageItems.length - 1];

  const nextCursor =
    hasMore && lastItem
      ? encodeVaultItemCursor({
          version: 1,

          vaultId,

          includeDeleted: options.includeDeleted,

          snapshotAt: snapshotAt.toISOString(),

          updatedAt: lastItem.updatedAt.toISOString(),

          itemId: lastItem.id,
        })
      : null;

  return {
    items: encryptedItems,

    page: {
      hasMore,
      nextCursor,

      snapshotAt: snapshotAt.toISOString(),
    },
  };
}

interface SyncVaultItemsOptions {
  limit: number;

  cursor?: VaultItemSyncCursor;
}

export async function syncVaultItems(
  userId: string,
  vaultId: string,
  options: SyncVaultItemsOptions,
) {
  const vault = await prisma.vault.findFirst({
    where: {
      id: vaultId,
      userId,
    },

    select: {
      id: true,
    },
  });

  if (!vault) {
    throw new Error('VAULT_NOT_FOUND');
  }

  const afterChangeId = options.cursor ? BigInt(options.cursor.afterChangeId) : 0n;

  /*
   * Fetch one extra change so we know
   * whether another page exists.
   */
  const changes = await prisma.vaultItemChange.findMany({
    where: {
      vaultId,

      id: {
        gt: afterChangeId,
      },
    },

    orderBy: {
      id: 'asc',
    },

    take: options.limit + 1,
  });

  const hasMore = changes.length > options.limit;

  const pageChanges = hasMore ? changes.slice(0, options.limit) : changes;

  const vaultKeyVersion = pageChanges.some((change) => change.kind !== 'DELETED')
    ? await getCurrentVaultKeyVersion(vaultId)
    : undefined;

  const resultChanges = await Promise.all(
    pageChanges.map(async (change) => {
      /*
       * A delete is a tombstone.
       * No ciphertext needs to be sent.
       */
      if (change.kind === 'DELETED') {
        return {
          changeId: change.id.toString(),

          kind: change.kind,

          itemId: change.itemId,

          revisionNumber: change.revisionNumber,

          deletedAt: change.deletedAt,

          changedAt: change.changedAt,

          item: null,
        };
      }

      if (vaultKeyVersion === undefined) {
        throw new Error('CRYPTO_STATE_INVALID');
      }

      const encryptedItem = await buildEncryptedItemResponse(
        vaultId,
        change.itemId,
        change.revisionNumber,
        vaultKeyVersion,
        change.changedAt,
      );

      return {
        changeId: change.id.toString(),

        kind: change.kind,

        itemId: change.itemId,

        revisionNumber: change.revisionNumber,

        deletedAt: change.deletedAt,

        changedAt: change.changedAt,

        item: {
          ...encryptedItem,

          deletedAt: change.deletedAt,
        },
      };
    }),
  );

  const lastChange = pageChanges[pageChanges.length - 1];

  /*
   * A sync cursor is always returned,
   * including when there were no changes.
   *
   * That lets the client persist a durable
   * checkpoint and poll again later.
   */
  const nextAfterChangeId = lastChange ? lastChange.id : afterChangeId;

  return {
    changes: resultChanges,

    sync: {
      hasMore,

      nextCursor: encodeVaultItemSyncCursor({
        version: 1,

        vaultId,

        afterChangeId: nextAfterChangeId.toString(),
      }),
    },
  };
}

async function cleanupExpiredVaultItemReservations(
  tx: Prisma.TransactionClient,
  vaultId: string,
  now = new Date(),
) {
  const cutoff = new Date(now.getTime() - VAULT_ITEM_RESERVATION_TTL_MS);

  const result = await tx.vaultItem.deleteMany({
    where: {
      vaultId,

      currentRevisionNumber: 0,

      deletedAt: null,

      createdAt: {
        lte: cutoff,
      },

      /*
       * Defensive check:
       * a reservation must not have
       * persisted revisions.
       */
      revisions: {
        none: {},
      },
    },
  });

  return result.count;
}
