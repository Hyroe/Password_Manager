import { describe, expect, it } from 'vitest';

import type { VaultSearchEntry } from './vaultSearch';

import { createVaultListView } from './vaultList';

const entries: VaultSearchEntry[] = [
  {
    itemId: 'item-3',
    name: 'GitHub',
    username: 'z@example.com',
    urls: ['https://github.com'],
  },
  {
    itemId: 'item-1',
    name: 'amazon',
    username: 'buyer@example.com',
    urls: ['https://amazon.com'],
  },
  {
    itemId: 'item-2',
    name: 'GitHub',
    username: 'a@example.com',
    urls: ['https://github.com/login'],
  },
];

describe('vault list view', () => {
  it('sorts entries by name case-insensitively', () => {
    const view = createVaultListView(entries, '');

    expect(view.entries.map((entry) => entry.itemId)).toEqual(['item-1', 'item-2', 'item-3']);
  });

  it('uses username as the secondary sort key', () => {
    const view = createVaultListView(entries, '');

    const githubEntries = view.entries.filter((entry) => entry.name === 'GitHub');

    expect(githubEntries.map((entry) => entry.username)).toEqual([
      'a@example.com',
      'z@example.com',
    ]);
  });

  it('uses item id as a deterministic final sort key', () => {
    const duplicateEntries: VaultSearchEntry[] = [
      {
        itemId: 'item-b',
        name: 'Example',
        username: 'user',
        urls: [],
      },
      {
        itemId: 'item-a',
        name: 'Example',
        username: 'user',
        urls: [],
      },
    ];

    const view = createVaultListView(duplicateEntries, '');

    expect(view.entries.map((entry) => entry.itemId)).toEqual(['item-a', 'item-b']);
  });

  it('does not mutate the source array', () => {
    const source = [...entries];

    const originalOrder = source.map((entry) => entry.itemId);

    createVaultListView(source, '');

    expect(source.map((entry) => entry.itemId)).toEqual(originalOrder);
  });

  it('filters using the existing vault search model', () => {
    const view = createVaultListView(entries, 'github');

    expect(view.entries.map((entry) => entry.itemId)).toEqual(['item-2', 'item-3']);

    expect(view.totalCount).toBe(3);
    expect(view.visibleCount).toBe(2);
    expect(view.hasQuery).toBe(true);
  });

  it('supports username search', () => {
    const view = createVaultListView(entries, 'buyer@example.com');

    expect(view.entries.map((entry) => entry.itemId)).toEqual(['item-1']);
  });

  it('supports URL search', () => {
    const view = createVaultListView(entries, 'amazon.com');

    expect(view.entries.map((entry) => entry.itemId)).toEqual(['item-1']);
  });

  it('reports an empty vault separately from empty search results', () => {
    const view = createVaultListView([], 'github');

    expect(view).toMatchObject({
      totalCount: 0,
      visibleCount: 0,
      hasQuery: true,
      emptyState: 'EMPTY_VAULT',
    });
  });

  it('reports no search results when the vault contains other entries', () => {
    const view = createVaultListView(entries, 'does-not-exist');

    expect(view).toMatchObject({
      totalCount: 3,
      visibleCount: 0,
      hasQuery: true,
      emptyState: 'NO_SEARCH_RESULTS',
    });
  });

  it('treats whitespace-only queries as no search', () => {
    const view = createVaultListView(entries, '   ');

    expect(view.hasQuery).toBe(false);
    expect(view.visibleCount).toBe(3);
    expect(view.emptyState).toBeNull();
  });

  it('has no empty state when entries are visible', () => {
    const view = createVaultListView(entries, 'git');

    expect(view.visibleCount).toBe(2);
    expect(view.emptyState).toBeNull();
  });
});
