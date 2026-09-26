import { prisma } from '../../lib/prisma.js';
import { encodeBase64Url } from '../../lib/base64Url.js';

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
  const vault = await prisma.vault.findFirst({
    where: {
      id: vaultId,
      userId,
    },
  });

  if (!vault) {
    throw new Error('VAULT_NOT_FOUND');
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

  const item = await prisma.vaultItem.create({
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

    aad: {
      itemKey: itemKeyAad(vaultId, item.id, revisionNumber, vaultKeyEnvelope.vaultKeyVersion),

      payload: itemPayloadAad(vaultId, item.id, revisionNumber, ITEM_KEY_VERSION),
    },
  };
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

    return {
      id: item.id,

      vaultId,

      revisionNumber: input.revisionNumber,

      createdAt: revision.createdAt,
    };
  });
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
  };
}

export async function listEncryptedVaultItems(userId: string, vaultId: string) {
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

  const items = await prisma.vaultItem.findMany({
    where: {
      vaultId,
      deletedAt: null,

      currentRevisionNumber: {
        gt: 0,
      },
    },

    select: {
      id: true,
      currentRevisionNumber: true,
    },

    orderBy: {
      updatedAt: 'desc',
    },
  });

  return Promise.all(
    items.map((item) =>
      buildEncryptedItemResponse(vaultId, item.id, item.currentRevisionNumber, vaultKeyVersion),
    ),
  );
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
    },
  });

  if (!item) {
    throw new Error('ITEM_NOT_FOUND');
  }

  const vaultKeyVersion = await getCurrentVaultKeyVersion(vaultId);

  return buildEncryptedItemResponse(vaultId, item.id, item.currentRevisionNumber, vaultKeyVersion);
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

    return {
      id: itemId,
      vaultId,

      revisionNumber: input.revisionNumber,

      createdAt: revision.createdAt,
    };
  });
}
