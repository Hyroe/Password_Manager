import { z } from 'zod';

const vaultItemCursorSchema = z.object({
  version: z.literal(1),

  vaultId: z.string().uuid(),

  includeDeleted: z.boolean(),

  snapshotAt: z.string().datetime({
    offset: true,
  }),

  updatedAt: z.string().datetime({
    offset: true,
  }),

  itemId: z.string().uuid(),
});

export interface VaultItemCursor {
  version: 1;

  vaultId: string;

  includeDeleted: boolean;

  snapshotAt: string;
  updatedAt: string;

  itemId: string;
}

export function encodeVaultItemCursor(cursor: VaultItemCursor): string {
  return Buffer.from(JSON.stringify(cursor), 'utf8').toString('base64url');
}

export function decodeVaultItemCursor(value: string): VaultItemCursor {
  if (!value || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('INVALID_PAGINATION_CURSOR');
  }

  const decoded = Buffer.from(value, 'base64url');

  if (decoded.toString('base64url') !== value) {
    throw new Error('INVALID_PAGINATION_CURSOR');
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(decoded.toString('utf8'));
  } catch {
    throw new Error('INVALID_PAGINATION_CURSOR');
  }

  const result = vaultItemCursorSchema.safeParse(parsed);

  if (!result.success) {
    throw new Error('INVALID_PAGINATION_CURSOR');
  }

  return result.data;
}
