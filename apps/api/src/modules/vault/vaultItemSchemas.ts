import { z } from 'zod';

import {
  ITEM_CIPHERTEXT_VERSION,
  ITEM_KEY_ENVELOPE_VERSION,
  ITEM_KEY_VERSION,
  ITEM_PAYLOAD_VERSION,
} from './vaultItemCryptoPolicy.js';

export const vaultIdParamsSchema = z.object({
  vaultId: z.string().uuid(),
});

export const encryptedVaultItemSchema = z.object({
  itemId: z.string().uuid(),

  revisionNumber: z.literal(1),

  payloadVersion: z.literal(ITEM_PAYLOAD_VERSION),

  ciphertextVersion: z.literal(ITEM_CIPHERTEXT_VERSION),

  itemKeyVersion: z.literal(ITEM_KEY_VERSION),

  vaultKeyVersion: z.number().int().positive(),

  envelopeVersion: z.literal(ITEM_KEY_ENVELOPE_VERSION),

  itemKeyEnvelope: z.string().min(1).max(128),

  ciphertext: z.string().min(1).max(140_000),
});

export const vaultItemParamsSchema = z.object({
  vaultId: z.string().uuid(),
  itemId: z.string().uuid(),
});

export const vaultItemUpdateOptionsSchema = z.object({
  expectedRevisionNumber: z.number().int().positive(),
});

export const encryptedVaultItemRevisionSchema = z.object({
  expectedRevisionNumber: z.number().int().positive(),

  revisionNumber: z.number().int().positive(),

  payloadVersion: z.literal(ITEM_PAYLOAD_VERSION),

  ciphertextVersion: z.literal(ITEM_CIPHERTEXT_VERSION),

  itemKeyVersion: z.literal(ITEM_KEY_VERSION),

  vaultKeyVersion: z.number().int().positive(),

  envelopeVersion: z.literal(ITEM_KEY_ENVELOPE_VERSION),

  itemKeyEnvelope: z.string().min(1).max(128),

  ciphertext: z.string().min(1).max(140_000),
});

export const vaultItemDeleteSchema = z.object({
  expectedRevisionNumber: z.number().int().positive(),
});
