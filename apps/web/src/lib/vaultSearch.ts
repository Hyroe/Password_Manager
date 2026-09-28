import type { LoginItemPayload } from './cryptoCore';

export interface VaultSearchEntry {
  itemId: string;
  name: string;
  username: string;
  urls: string[];
}

export function createVaultSearchEntry(itemId: string, login: LoginItemPayload): VaultSearchEntry {
  return {
    itemId,
    name: login.name,
    username: login.username,
    urls: [...login.urls],
  };
}

export function filterVaultSearchEntries(
  entries: VaultSearchEntry[],
  query: string,
): VaultSearchEntry[] {
  const normalizedQuery = query.trim().toLowerCase();

  if (!normalizedQuery) {
    return entries;
  }

  return entries.filter((entry) => {
    const searchableValues = [entry.itemId, entry.name, entry.username, ...entry.urls];

    return searchableValues.some((value) => value.toLowerCase().includes(normalizedQuery));
  });
}
