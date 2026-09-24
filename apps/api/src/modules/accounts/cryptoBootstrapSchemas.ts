import { z } from 'zod';

import {
  ARGON2_ITERATIONS,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
  CRYPTO_PROTOCOL_VERSION,
  KDF_PROFILE_VERSION,
  KEY_ENVELOPE_VERSION,
} from './cryptoBootstrapPolicy.js';

const base64UrlSchema = z
  .string()
  .min(1)
  .max(512)
  .regex(/^[A-Za-z0-9_-]+$/);

export const cryptoBootstrapOptionsSchema = z.object({
  registrationId: z.string().uuid(),
  bootstrapToken: z.string().min(1).max(512),
});

export const completeCryptoBootstrapSchema = z
  .object({
    registrationId: z.string().uuid(),
    bootstrapToken: z.string().min(1).max(512),
    bootstrapContextId: z.string().uuid(),

    protocolVersion: z.literal(CRYPTO_PROTOCOL_VERSION),

    kdf: z.object({
      algorithm: z.literal('ARGON2ID'),
      profileVersion: z.literal(KDF_PROFILE_VERSION),

      memoryKib: z.literal(ARGON2_MEMORY_KIB),
      iterations: z.literal(ARGON2_ITERATIONS),
      parallelism: z.literal(ARGON2_PARALLELISM),

      salt: base64UrlSchema,
    }),

    envelope: z.object({
      version: z.literal(KEY_ENVELOPE_VERSION),

      rootKey: base64UrlSchema,
      recoveryRootKey: base64UrlSchema,
      vaultKey: base64UrlSchema,
    }),
  })
  .strict();

export type CryptoBootstrapOptionsInput = z.infer<typeof cryptoBootstrapOptionsSchema>;

export type CompleteCryptoBootstrapInput = z.infer<typeof completeCryptoBootstrapSchema>;
