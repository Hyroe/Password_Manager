import { describe, expect, it } from 'vitest';

import {
  createVaultSearchEntry,
  filterVaultSearchEntries,
  type VaultSearchEntry,
} from './vaultSearch';

describe('vault search', () => {
  it('creates a search entry without retaining password or notes', () => {
    const entry = createVaultSearchEntry('item-1', {
      name: 'GitHub',
      username: 'daniel@example.com',
      password: 'super-secret-password',
      urls: ['https://github.com'],
      notes: 'private recovery information',
      schemaVersion: 1,
      itemType: 'LOGIN',
    });

    expect(entry).toEqual({
      itemId: 'item-1',
      name: 'GitHub',
      username: 'daniel@example.com',
      urls: ['https://github.com'],
    });

    expect('password' in entry).toBe(false);
    expect('notes' in entry).toBe(false);
  });

  it('returns all entries when the query is empty', () => {
    const entries: VaultSearchEntry[] = [
      {
        itemId: 'item-1',
        name: 'GitHub',
        username: 'daniel@example.com',
        urls: ['https://github.com'],
      },
      {
        itemId: 'item-2',
        name: 'Example',
        username: 'user@example.org',
        urls: ['https://example.org'],
      },
    ];

    expect(filterVaultSearchEntries(entries, '')).toEqual(entries);

    expect(filterVaultSearchEntries(entries, '   ')).toEqual(entries);
  });

  it('matches names case-insensitively', () => {
    const entries: VaultSearchEntry[] = [
      {
        itemId: 'item-1',
        name: 'GitHub',
        username: 'daniel@example.com',
        urls: ['https://github.com'],
      },
      {
        itemId: 'item-2',
        name: 'Example',
        username: 'user@example.org',
        urls: ['https://example.org'],
      },
    ];

    expect(filterVaultSearchEntries(entries, 'GITHUB')).toEqual([entries[0]]);
  });

  it('matches usernames', () => {
    const entries: VaultSearchEntry[] = [
      {
        itemId: 'item-1',
        name: 'GitHub',
        username: 'daniel@example.com',
        urls: ['https://github.com'],
      },
      {
        itemId: 'item-2',
        name: 'Example',
        username: 'someone@other.net',
        urls: ['https://example.org'],
      },
    ];

    expect(filterVaultSearchEntries(entries, 'daniel@')).toEqual([entries[0]]);
  });

  it('matches URLs', () => {
    const entries: VaultSearchEntry[] = [
      {
        itemId: 'item-1',
        name: 'GitHub',
        username: 'daniel@example.com',
        urls: ['https://github.com'],
      },
      {
        itemId: 'item-2',
        name: 'Example',
        username: 'user@example.org',
        urls: ['https://example.org'],
      },
    ];

    expect(filterVaultSearchEntries(entries, 'example.org')).toEqual([entries[1]]);
  });

  it('matches item ids', () => {
    const entries: VaultSearchEntry[] = [
      {
        itemId: 'vault-item-abc123',
        name: 'GitHub',
        username: '',
        urls: [],
      },
      {
        itemId: 'vault-item-def456',
        name: 'Example',
        username: '',
        urls: [],
      },
    ];

    expect(filterVaultSearchEntries(entries, 'abc123')).toEqual([entries[0]]);
  });

  it('returns an empty collection when nothing matches', () => {
    const entries: VaultSearchEntry[] = [
      {
        itemId: 'item-1',
        name: 'GitHub',
        username: 'daniel@example.com',
        urls: ['https://github.com'],
      },
    ];

    expect(filterVaultSearchEntries(entries, 'bitwarden')).toEqual([]);
  });
});
