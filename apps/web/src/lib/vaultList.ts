import { filterVaultSearchEntries, type VaultSearchEntry } from './vaultSearch';

export type VaultListEmptyState = 'EMPTY_VAULT' | 'NO_SEARCH_RESULTS' | null;

export interface VaultListView {
  entries: VaultSearchEntry[];
  totalCount: number;
  visibleCount: number;
  hasQuery: boolean;
  emptyState: VaultListEmptyState;
}

function compareText(left: string, right: string): number {
  const normalizedLeft = left.toLowerCase();
  const normalizedRight = right.toLowerCase();

  if (normalizedLeft < normalizedRight) {
    return -1;
  }

  if (normalizedLeft > normalizedRight) {
    return 1;
  }

  return 0;
}

function compareVaultEntries(left: VaultSearchEntry, right: VaultSearchEntry): number {
  const byName = compareText(left.name, right.name);

  if (byName !== 0) {
    return byName;
  }

  const byUsername = compareText(left.username, right.username);

  if (byUsername !== 0) {
    return byUsername;
  }

  return compareText(left.itemId, right.itemId);
}

export function createVaultListView(
  entries: readonly VaultSearchEntry[],
  query: string,
): VaultListView {
  const normalizedQuery = query.trim();

  const filteredEntries = filterVaultSearchEntries([...entries], normalizedQuery);

  const sortedEntries = [...filteredEntries].sort(compareVaultEntries);

  const totalCount = entries.length;
  const visibleCount = sortedEntries.length;
  const hasQuery = normalizedQuery.length > 0;

  let emptyState: VaultListEmptyState = null;

  if (totalCount === 0) {
    emptyState = 'EMPTY_VAULT';
  } else if (hasQuery && visibleCount === 0) {
    emptyState = 'NO_SEARCH_RESULTS';
  }

  return {
    entries: sortedEntries,
    totalCount,
    visibleCount,
    hasQuery,
    emptyState,
  };
}
