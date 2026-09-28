import { z } from 'zod';

import {
  ARGON2_ITERATIONS,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
  CRYPTO_PROTOCOL_VERSION,
  KDF_PROFILE_VERSION,
  KEY_ENVELOPE_VERSION,
} from '../accounts/cryptoBootstrapPolicy.js';

const base64UrlSchema = z
  .string()
  .min(1)
  .max(512)
  .regex(/^[A-Za-z0-9_-]+$/);

export const changeMasterPasswordSchema = z
  .object({
    protocolVersion: z.literal(CRYPTO_PROTOCOL_VERSION),

    kdf: z.object({
      algorithm: z.literal('ARGON2ID'),

      profileVersion: z.literal(KDF_PROFILE_VERSION),

      memoryKib: z.literal(ARGON2_MEMORY_KIB),

      iterations: z.literal(ARGON2_ITERATIONS),

      parallelism: z.literal(ARGON2_PARALLELISM),

      salt: base64UrlSchema,
    }),

    rootKey: z.object({
      keyVersion: z.number().int().positive(),

      envelopeVersion: z.literal(KEY_ENVELOPE_VERSION),

      expectedUpdatedAt: z.string().datetime({
        offset: true,
      }),

      envelope: base64UrlSchema,
    }),
  })
  .strict();

export type ChangeMasterPasswordInput = z.infer<typeof changeMasterPasswordSchema>;
