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

export const vaultItemRestoreSchema = z.object({
  expectedRevisionNumber: z.number().int().positive(),
});

export const vaultItemListQuerySchema = z.object({
  includeDeleted: z.enum(['true', 'false']).optional().default('false'),

  limit: z.coerce.number().int().min(1).max(100).optional().default(50),

  cursor: z.string().min(1).max(2048).optional(),
});

export const vaultItemSyncQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(200).optional().default(100),

  cursor: z.string().min(1).max(2048).optional(),
});
