import { describe, expect, it } from 'vitest';

import { itemKeyAad, itemPayloadAad } from './vaultItemCryptoContext';

describe('vault item crypto context', () => {
  it('builds deterministic item key AAD', () => {
    expect(itemKeyAad('vault-1', 'item-1', 3, 2)).toBe(
      'pm:v1:item-key:vault:vault-1:item:item-1:revision:3:vault-key-version:2',
    );
  });

  it('builds deterministic payload AAD', () => {
    expect(itemPayloadAad('vault-1', 'item-1', 3, 1)).toBe(
      'pm:v1:item-payload:vault:vault-1:item:item-1:revision:3:item-key-version:1',
    );
  });
});
