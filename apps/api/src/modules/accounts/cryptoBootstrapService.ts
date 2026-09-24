import { prisma } from '../../lib/prisma.js';
import { verifySecurityToken } from '../../lib/securityTokens.js';
import type { CompleteCryptoBootstrapInput } from './cryptoBootstrapSchemas.js';
import { decodeCanonicalBase64Url } from './cryptoBootstrapEncoding.js';

import {
  ARGON2_ITERATIONS,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
  CRYPTO_PROTOCOL_VERSION,
  KDF_PROFILE_VERSION,
  KDF_SALT_BYTES,
  KEY_ENVELOPE_BYTES,
  KEY_ENVELOPE_VERSION,
  recoveryRootKeyAad,
  rootKeyAad,
  vaultKeyAad,
} from './cryptoBootstrapPolicy.js';

import { Prisma } from '../../generated/prisma/client.js';

const BOOTSTRAP_CONTEXT_TTL_MS = 15 * 60 * 1000;

async function getEligibleBootstrapRegistration(registrationId: string, bootstrapToken: string) {
  const attempt = await prisma.registrationAttempt.findUnique({
    where: {
      id: registrationId,
    },
  });

  if (
    !attempt ||
    attempt.status !== 'PASSKEY_REGISTERED' ||
    !attempt.bootstrapTokenHash ||
    !attempt.bootstrapTokenExpiresAt ||
    attempt.bootstrapTokenExpiresAt <= new Date() ||
    !verifySecurityToken(bootstrapToken, attempt.bootstrapTokenHash)
  ) {
    throw new Error('INVALID_BOOTSTRAP');
  }

  return attempt;
}

export async function createCryptoBootstrapOptions(registrationId: string, bootstrapToken: string) {
  const attempt = await getEligibleBootstrapRegistration(registrationId, bootstrapToken);

  const existing = await prisma.accountBootstrapContext.findUnique({
    where: {
      registrationAttemptId: attempt.id,
    },
  });

  let context = existing;

  if (!context || context.expiresAt <= new Date() || context.consumedAt) {
    if (context) {
      await prisma.accountBootstrapContext.delete({
        where: {
          id: context.id,
        },
      });
    }

    context = await prisma.accountBootstrapContext.create({
      data: {
        registrationAttemptId: attempt.id,
        expiresAt: new Date(Date.now() + BOOTSTRAP_CONTEXT_TTL_MS),
      },
    });
  }

  return {
    bootstrapContextId: context.id,

    cryptoProfileId: context.cryptoProfileId,
    vaultId: context.personalVaultId,

    protocolVersion: CRYPTO_PROTOCOL_VERSION,

    kdf: {
      algorithm: 'ARGON2ID' as const,
      profileVersion: KDF_PROFILE_VERSION,

      memoryKib: ARGON2_MEMORY_KIB,
      iterations: ARGON2_ITERATIONS,
      parallelism: ARGON2_PARALLELISM,

      saltBytes: KDF_SALT_BYTES,
    },

    envelope: {
      version: KEY_ENVELOPE_VERSION,

      rootKeyAad: rootKeyAad(context.cryptoProfileId),

      recoveryRootKeyAad: recoveryRootKeyAad(context.cryptoProfileId),

      vaultKeyAad: vaultKeyAad(context.personalVaultId),
    },
  };
}

export async function completeCryptoBootstrap(input: CompleteCryptoBootstrapInput) {
  const kdfSalt = decodeCanonicalBase64Url(input.kdf.salt, KDF_SALT_BYTES);

  const rootKeyEnvelope = decodeCanonicalBase64Url(input.envelope.rootKey, KEY_ENVELOPE_BYTES);

  const recoveryRootKeyEnvelope = decodeCanonicalBase64Url(
    input.envelope.recoveryRootKey,
    KEY_ENVELOPE_BYTES,
  );

  const vaultKeyEnvelope = decodeCanonicalBase64Url(input.envelope.vaultKey, KEY_ENVELOPE_BYTES);

  try {
    return await prisma.$transaction(async (tx) => {
      const now = new Date();

      const attempt = await tx.registrationAttempt.findUnique({
        where: {
          id: input.registrationId,
        },
      });

      if (
        !attempt ||
        !attempt.bootstrapTokenHash ||
        !attempt.bootstrapTokenExpiresAt ||
        attempt.bootstrapTokenExpiresAt <= now ||
        !verifySecurityToken(input.bootstrapToken, attempt.bootstrapTokenHash)
      ) {
        throw new Error('INVALID_BOOTSTRAP');
      }

      const context = await tx.accountBootstrapContext.findUnique({
        where: {
          id: input.bootstrapContextId,
        },
      });

      if (!context || context.registrationAttemptId !== attempt.id) {
        throw new Error('INVALID_BOOTSTRAP');
      }

      /*
       * Idempotent retry.
       *
       * If account activation already succeeded but the client lost
       * the HTTP response, the same still-valid bootstrap capability
       * can recover the successful result.
       */
      if (attempt.status === 'COMPLETED') {
        if (!attempt.completedUserId || !context.consumedAt) {
          throw new Error('INVALID_BOOTSTRAP');
        }

        return {
          userId: attempt.completedUserId,
          vaultId: context.personalVaultId,
          status: 'ACTIVE' as const,
          alreadyCompleted: true,
        };
      }

      if (
        attempt.status !== 'PASSKEY_REGISTERED' ||
        !attempt.emailVerifiedAt ||
        !attempt.webauthnUserId ||
        context.expiresAt <= now ||
        context.consumedAt
      ) {
        throw new Error('INVALID_BOOTSTRAP');
      }

      /*
       * Atomic compare-and-set.
       *
       * Two requests cannot both consume the same bootstrap context.
       */
      const consumed = await tx.accountBootstrapContext.updateMany({
        where: {
          id: context.id,
          registrationAttemptId: attempt.id,
          consumedAt: null,
          expiresAt: {
            gt: now,
          },
        },
        data: {
          consumedAt: now,
        },
      });

      if (consumed.count !== 1) {
        throw new Error('INVALID_BOOTSTRAP');
      }

      const registrationPasskey = await tx.registrationPasskey.findFirst({
        where: {
          registrationAttemptId: attempt.id,
        },
      });

      if (!registrationPasskey) {
        throw new Error('INVALID_BOOTSTRAP');
      }

      const existingUser = await tx.user.findUnique({
        where: {
          normalizedEmail: attempt.normalizedEmail,
        },
        select: {
          id: true,
        },
      });

      if (existingUser) {
        throw new Error('ACCOUNT_ALREADY_EXISTS');
      }

      const user = await tx.user.create({
        data: {
          email: attempt.email,
          normalizedEmail: attempt.normalizedEmail,

          status: 'ACTIVE',
          emailVerifiedAt: attempt.emailVerifiedAt,

          webauthnUserId: attempt.webauthnUserId,
        },
        select: {
          id: true,
        },
      });

      await tx.passkeyCredential.create({
        data: {
          userId: user.id,

          credentialId: registrationPasskey.credentialId,

          publicKey: registrationPasskey.publicKey,

          counter: registrationPasskey.counter,

          deviceType: registrationPasskey.deviceType,

          backedUp: registrationPasskey.backedUp,

          transports: registrationPasskey.transports,
        },
      });

      await tx.userCryptoProfile.create({
        data: {
          id: context.cryptoProfileId,
          userId: user.id,

          protocolVersion: input.protocolVersion,

          kdfAlgorithm: input.kdf.algorithm,

          kdfProfileVersion: input.kdf.profileVersion,

          argon2MemoryKib: input.kdf.memoryKib,

          argon2Iterations: input.kdf.iterations,

          argon2Parallelism: input.kdf.parallelism,

          kdfSalt,
        },
      });

      await tx.rootKeyEnvelope.create({
        data: {
          cryptoProfileId: context.cryptoProfileId,

          keyVersion: 1,
          envelopeVersion: input.envelope.version,

          encryptedKey: rootKeyEnvelope,
        },
      });

      await tx.recoveryEnvelope.create({
        data: {
          cryptoProfileId: context.cryptoProfileId,

          recoveryVersion: 1,
          rootKeyVersion: 1,

          envelopeVersion: input.envelope.version,

          encryptedKey: recoveryRootKeyEnvelope,
        },
      });

      await tx.vault.create({
        data: {
          id: context.personalVaultId,
          userId: user.id,
          kind: 'PERSONAL',
        },
      });

      await tx.vaultKeyEnvelope.create({
        data: {
          vaultId: context.personalVaultId,

          vaultKeyVersion: 1,
          rootKeyVersion: 1,

          envelopeVersion: input.envelope.version,

          encryptedKey: vaultKeyEnvelope,
        },
      });

      /*
       * Temporary registration credential has now been promoted.
       */
      await tx.registrationPasskey.deleteMany({
        where: {
          registrationAttemptId: attempt.id,
        },
      });

      await tx.webAuthnChallenge.deleteMany({
        where: {
          registrationAttemptId: attempt.id,
        },
      });

      await tx.registrationAttempt.update({
        where: {
          id: attempt.id,
        },
        data: {
          status: 'COMPLETED',

          completedUserId: user.id,
          completedAt: now,

          registrationTokenHash: null,
          registrationTokenExpiresAt: null,
        },
      });

      return {
        userId: user.id,
        vaultId: context.personalVaultId,
        status: 'ACTIVE' as const,
        alreadyCompleted: false,
      };
    });
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
      throw new Error('ACCOUNT_ALREADY_EXISTS', {
        cause: error,
      });
    }

    throw error;
  }
}
