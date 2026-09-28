import {
  CRYPTO_PROTOCOL_VERSION,
  KDF_SALT_BYTES,
  KEY_ENVELOPE_BYTES,
  KEY_ENVELOPE_VERSION,
  recoveryRootKeyAad,
  rootKeyAad,
  vaultKeyAad,
} from '../accounts/cryptoBootstrapPolicy.js';

import type { ChangeMasterPasswordInput } from './vaultMasterPasswordSchemas.js';

import type { CompleteMasterPasswordRecoveryInput } from './vaultRecoverySchemas.js';

import { decodeCanonicalBase64Url } from '../accounts/cryptoBootstrapEncoding.js';

import { encodeBase64Url } from '../../lib/base64Url.js';

import { prisma } from '../../lib/prisma.js';

export async function getVaultUnlockMaterial(userId: string) {
  const profile = await prisma.userCryptoProfile.findUnique({
    where: {
      userId,
    },

    include: {
      rootKeyEnvelopes: {
        orderBy: {
          keyVersion: 'desc',
        },

        take: 1,
      },
    },
  });

  if (!profile) {
    throw new Error('CRYPTO_STATE_INVALID');
  }

  if (profile.protocolVersion !== CRYPTO_PROTOCOL_VERSION) {
    throw new Error('CRYPTO_PROTOCOL_UNSUPPORTED');
  }

  const rootEnvelope = profile.rootKeyEnvelopes[0];

  if (!rootEnvelope) {
    throw new Error('CRYPTO_STATE_INVALID');
  }

  const vault = await prisma.vault.findFirst({
    where: {
      userId,
      kind: 'PERSONAL',
    },
  });

  if (!vault) {
    throw new Error('CRYPTO_STATE_INVALID');
  }

  const vaultEnvelope = await prisma.vaultKeyEnvelope.findFirst({
    where: {
      vaultId: vault.id,

      rootKeyVersion: rootEnvelope.keyVersion,
    },

    orderBy: {
      vaultKeyVersion: 'desc',
    },
  });

  if (!vaultEnvelope) {
    throw new Error('CRYPTO_STATE_INVALID');
  }

  return {
    protocolVersion: profile.protocolVersion,

    cryptoProfileId: profile.id,

    kdf: {
      algorithm: profile.kdfAlgorithm,

      profileVersion: profile.kdfProfileVersion,

      memoryKib: profile.argon2MemoryKib,

      iterations: profile.argon2Iterations,

      parallelism: profile.argon2Parallelism,

      salt: encodeBase64Url(profile.kdfSalt),
    },

    rootKey: {
      keyVersion: rootEnvelope.keyVersion,

      envelopeVersion: rootEnvelope.envelopeVersion,

      updatedAt: rootEnvelope.updatedAt.toISOString(),

      envelope: encodeBase64Url(rootEnvelope.encryptedKey),

      aad: rootKeyAad(profile.id, rootEnvelope.keyVersion),
    },

    vault: {
      id: vault.id,
      kind: vault.kind,

      keyVersion: vaultEnvelope.vaultKeyVersion,

      rootKeyVersion: vaultEnvelope.rootKeyVersion,

      envelopeVersion: vaultEnvelope.envelopeVersion,

      envelope: encodeBase64Url(vaultEnvelope.encryptedKey),

      aad: vaultKeyAad(vault.id, vaultEnvelope.vaultKeyVersion),
    },
  };
}

export async function getMasterPasswordRecoveryMaterial(userId: string) {
  /*
   * Recovery is only available for an
   * authenticated account with a complete
   * crypto profile.
   */
  const profile = await prisma.userCryptoProfile.findUnique({
    where: {
      userId,
    },

    include: {
      rootKeyEnvelopes: {
        orderBy: {
          keyVersion: 'desc',
        },

        take: 1,
      },
    },
  });

  if (!profile) {
    throw new Error('CRYPTO_STATE_INVALID');
  }

  if (profile.protocolVersion !== CRYPTO_PROTOCOL_VERSION) {
    throw new Error('CRYPTO_PROTOCOL_UNSUPPORTED');
  }

  const rootEnvelope = profile.rootKeyEnvelopes[0];

  if (!rootEnvelope) {
    throw new Error('CRYPTO_STATE_INVALID');
  }

  /*
   * Recovery must target the same ARK
   * version that is currently active.
   *
   * We therefore select the newest
   * RecoveryEnvelope associated with that
   * root-key version.
   */
  const recoveryEnvelope = await prisma.recoveryEnvelope.findFirst({
    where: {
      cryptoProfileId: profile.id,

      rootKeyVersion: rootEnvelope.keyVersion,
    },

    orderBy: {
      recoveryVersion: 'desc',
    },
  });

  if (!recoveryEnvelope) {
    throw new Error('CRYPTO_STATE_INVALID');
  }

  return {
    protocolVersion: profile.protocolVersion,

    cryptoProfileId: profile.id,

    /*
     * The existing salt is deliberately
     * NOT returned.
     *
     * Recovery creates a fresh KDF salt
     * locally inside WASM.
     */
    kdf: {
      algorithm: profile.kdfAlgorithm,

      profileVersion: profile.kdfProfileVersion,

      memoryKib: profile.argon2MemoryKib,

      iterations: profile.argon2Iterations,

      parallelism: profile.argon2Parallelism,
    },

    /*
     * Encrypted ARK protected by the
     * Recovery Key-derived KEK.
     *
     * Recovery Key itself remains local
     * inside the Recovery Kit.
     */
    recoveryRootKey: {
      recoveryVersion: recoveryEnvelope.recoveryVersion,

      rootKeyVersion: recoveryEnvelope.rootKeyVersion,

      envelopeVersion: recoveryEnvelope.envelopeVersion,

      envelope: encodeBase64Url(recoveryEnvelope.encryptedKey),

      aad: recoveryRootKeyAad(profile.id, recoveryEnvelope.rootKeyVersion),
    },

    /*
     * Context for the new Master
     * Password-protected ARK envelope.
     *
     * We do not return the current
     * password-protected ciphertext
     * because recovery does not need it.
     */
    rootKey: {
      keyVersion: rootEnvelope.keyVersion,

      envelopeVersion: rootEnvelope.envelopeVersion,

      updatedAt: rootEnvelope.updatedAt.toISOString(),

      aad: rootKeyAad(profile.id, rootEnvelope.keyVersion),
    },
  };
}

export async function completeMasterPasswordRecovery(
  userId: string,
  input: CompleteMasterPasswordRecoveryInput,
): Promise<void> {
  const kdfSalt = decodeCanonicalBase64Url(input.kdf.salt, KDF_SALT_BYTES);

  const rootKeyEnvelope = decodeCanonicalBase64Url(input.rootKey.envelope, KEY_ENVELOPE_BYTES);

  /*
   * Envelope metadata must agree with the
   * actual serialized envelope.
   *
   * Current format:
   * byte 0 = envelope version.
   */
  if (rootKeyEnvelope[0] !== KEY_ENVELOPE_VERSION) {
    throw new Error('INVALID_CRYPTO_MATERIAL');
  }

  const expectedUpdatedAt = new Date(input.rootKey.expectedUpdatedAt);

  await prisma.$transaction(async (tx) => {
    const now = new Date();

    const profile = await tx.userCryptoProfile.findUnique({
      where: {
        userId,
      },

      include: {
        rootKeyEnvelopes: {
          orderBy: {
            keyVersion: 'desc',
          },

          take: 1,
        },
      },
    });

    if (!profile) {
      throw new Error('CRYPTO_STATE_INVALID');
    }

    if (profile.protocolVersion !== CRYPTO_PROTOCOL_VERSION) {
      throw new Error('CRYPTO_PROTOCOL_UNSUPPORTED');
    }

    const currentRootEnvelope = profile.rootKeyEnvelopes[0];

    if (!currentRootEnvelope) {
      throw new Error('CRYPTO_STATE_INVALID');
    }

    /*
     * Client must be completing recovery
     * against the ARK version it originally
     * received from GET /recovery.
     */
    if (
      currentRootEnvelope.keyVersion !== input.rootKey.keyVersion ||
      input.recovery.rootKeyVersion !== currentRootEnvelope.keyVersion
    ) {
      throw new Error('RECOVERY_CONFLICT');
    }

    const recoveryEnvelope = await tx.recoveryEnvelope.findFirst({
      where: {
        cryptoProfileId: profile.id,

        rootKeyVersion: currentRootEnvelope.keyVersion,
      },

      orderBy: {
        recoveryVersion: 'desc',
      },
    });

    if (!recoveryEnvelope) {
      throw new Error('CRYPTO_STATE_INVALID');
    }

    if (
      recoveryEnvelope.recoveryVersion !== input.recovery.recoveryVersion ||
      recoveryEnvelope.rootKeyVersion !== input.recovery.rootKeyVersion
    ) {
      throw new Error('RECOVERY_CONFLICT');
    }

    /*
     * OCC / compare-and-set.
     *
     * If another recovery already replaced
     * this envelope, updatedAt no longer
     * matches and this request must fail.
     */
    const rootUpdate = await tx.rootKeyEnvelope.updateMany({
      where: {
        id: currentRootEnvelope.id,

        cryptoProfileId: profile.id,

        keyVersion: currentRootEnvelope.keyVersion,

        updatedAt: expectedUpdatedAt,
      },

      data: {
        envelopeVersion: input.rootKey.envelopeVersion,

        encryptedKey: rootKeyEnvelope,

        updatedAt: now,
      },
    });

    if (rootUpdate.count !== 1) {
      throw new Error('RECOVERY_CONFLICT');
    }

    /*
     * Store the new Master Password KDF
     * configuration.
     *
     * Account Secret is never sent here.
     */
    await tx.userCryptoProfile.update({
      where: {
        id: profile.id,
      },

      data: {
        protocolVersion: input.protocolVersion,

        kdfAlgorithm: input.kdf.algorithm,

        kdfProfileVersion: input.kdf.profileVersion,

        argon2MemoryKib: input.kdf.memoryKib,

        argon2Iterations: input.kdf.iterations,

        argon2Parallelism: input.kdf.parallelism,

        kdfSalt,
      },
    });

    /*
     * Security boundary:
     *
     * Recovery invalidates every existing
     * authenticated session for the account,
     * including the one executing recovery.
     */
    await tx.session.updateMany({
      where: {
        userId,

        revokedAt: null,
      },

      data: {
        revokedAt: now,
      },
    });
  });
}

export async function changeMasterPassword(
  userId: string,
  input: ChangeMasterPasswordInput,
): Promise<void> {
  const kdfSalt = decodeCanonicalBase64Url(input.kdf.salt, KDF_SALT_BYTES);

  const rootKeyEnvelope = decodeCanonicalBase64Url(input.rootKey.envelope, KEY_ENVELOPE_BYTES);

  /*
   * Serialized envelope byte 0 contains
   * the envelope format version.
   */
  if (rootKeyEnvelope[0] !== KEY_ENVELOPE_VERSION) {
    throw new Error('INVALID_CRYPTO_MATERIAL');
  }

  const expectedUpdatedAt = new Date(input.rootKey.expectedUpdatedAt);

  await prisma.$transaction(async (tx) => {
    const now = new Date();

    const profile = await tx.userCryptoProfile.findUnique({
      where: {
        userId,
      },

      include: {
        rootKeyEnvelopes: {
          orderBy: {
            keyVersion: 'desc',
          },

          take: 1,
        },
      },
    });

    if (!profile) {
      throw new Error('CRYPTO_STATE_INVALID');
    }

    if (profile.protocolVersion !== CRYPTO_PROTOCOL_VERSION) {
      throw new Error('CRYPTO_PROTOCOL_UNSUPPORTED');
    }

    const currentRootEnvelope = profile.rootKeyEnvelopes[0];

    if (!currentRootEnvelope) {
      throw new Error('CRYPTO_STATE_INVALID');
    }

    /*
     * Client must be changing the same
     * ARK version it received from
     * GET /crypto/unlock.
     */
    if (currentRootEnvelope.keyVersion !== input.rootKey.keyVersion) {
      throw new Error('MASTER_PASSWORD_CHANGE_CONFLICT');
    }

    /*
     * Do not allow a normal password change
     * if the recovery path for this ARK has
     * disappeared.
     *
     * The RecoveryEnvelope itself remains
     * completely unchanged.
     */
    const recoveryEnvelope = await tx.recoveryEnvelope.findFirst({
      where: {
        cryptoProfileId: profile.id,

        rootKeyVersion: currentRootEnvelope.keyVersion,
      },

      orderBy: {
        recoveryVersion: 'desc',
      },
    });

    if (!recoveryEnvelope) {
      throw new Error('CRYPTO_STATE_INVALID');
    }

    /*
     * Optimistic concurrency control.
     *
     * If recovery or another password
     * change replaced this envelope after
     * the client loaded it, this update
     * must fail.
     */
    const rootUpdate = await tx.rootKeyEnvelope.updateMany({
      where: {
        id: currentRootEnvelope.id,

        cryptoProfileId: profile.id,

        keyVersion: currentRootEnvelope.keyVersion,

        updatedAt: expectedUpdatedAt,
      },

      data: {
        envelopeVersion: input.rootKey.envelopeVersion,

        encryptedKey: rootKeyEnvelope,

        updatedAt: now,
      },
    });

    if (rootUpdate.count !== 1) {
      throw new Error('MASTER_PASSWORD_CHANGE_CONFLICT');
    }

    /*
     * Persist the fresh KDF salt associated
     * with the new Master Password.
     *
     * The Master Password and Account Secret
     * never reach the server.
     */
    await tx.userCryptoProfile.update({
      where: {
        id: profile.id,
      },

      data: {
        protocolVersion: input.protocolVersion,

        kdfAlgorithm: input.kdf.algorithm,

        kdfProfileVersion: input.kdf.profileVersion,

        argon2MemoryKib: input.kdf.memoryKib,

        argon2Iterations: input.kdf.iterations,

        argon2Parallelism: input.kdf.parallelism,

        kdfSalt,
      },
    });

    /*
     * Changing the Master Password is a
     * security boundary.
     *
     * All sessions are revoked, including
     * the one performing this request.
     */
    await tx.session.updateMany({
      where: {
        userId,

        revokedAt: null,
      },

      data: {
        revokedAt: now,
      },
    });
  });
}
