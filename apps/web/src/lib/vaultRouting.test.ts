import { describe, expect, it } from 'vitest';

import { getVaultItemIdFromPath } from './vaultRouting';

describe('vault routing', () => {
  it('extracts the vault item id from an item route', () => {
    expect(getVaultItemIdFromPath('/vault/items/0199c531-a830-7000-8000-000000000001')).toBe(
      '0199c531-a830-7000-8000-000000000001',
    );
  });

  it('does not treat the vault root as an item route', () => {
    expect(getVaultItemIdFromPath('/vault')).toBeNull();
  });

  it('rejects unrelated and nested paths', () => {
    expect(getVaultItemIdFromPath('/settings/security')).toBeNull();

    expect(getVaultItemIdFromPath('/vault/items/item-1/history')).toBeNull();
  });
});
