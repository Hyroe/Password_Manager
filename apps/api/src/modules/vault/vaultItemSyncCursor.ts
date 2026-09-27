import { z } from 'zod';

const syncCursorSchema = z.object({
  version: z.literal(1),

  vaultId: z.string().uuid(),

  afterVersion: z.string().regex(/^\d+$/),
});

export interface VaultItemSyncCursor {
  version: 1;

  vaultId: string;

  afterVersion: string;
}

export function encodeVaultItemSyncCursor(cursor: VaultItemSyncCursor): string {
  return Buffer.from(JSON.stringify(cursor), 'utf8').toString('base64url');
}

export function decodeVaultItemSyncCursor(value: string): VaultItemSyncCursor {
  if (!value || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('INVALID_SYNC_CURSOR');
  }

  const decoded = Buffer.from(value, 'base64url');

  if (decoded.toString('base64url') !== value) {
    throw new Error('INVALID_SYNC_CURSOR');
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(decoded.toString('utf8'));
  } catch {
    throw new Error('INVALID_SYNC_CURSOR');
  }

  const result = syncCursorSchema.safeParse(parsed);

  if (!result.success) {
    throw new Error('INVALID_SYNC_CURSOR');
  }

  try {
    BigInt(result.data.afterVersion);
  } catch {
    throw new Error('INVALID_SYNC_CURSOR');
  }

  return result.data;
}
