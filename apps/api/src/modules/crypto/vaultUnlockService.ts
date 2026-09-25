import {
  CRYPTO_PROTOCOL_VERSION,
  rootKeyAad,
  vaultKeyAad,
} from '../accounts/cryptoBootstrapPolicy.js';

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
