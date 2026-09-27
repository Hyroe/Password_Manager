import { apiRequest } from './api';

export interface VaultItemReservation {
  vaultId: string;
  itemId: string;

  revisionNumber: number;

  payloadVersion: number;
  ciphertextVersion: number;

  itemKeyVersion: number;
  vaultKeyVersion: number;

  envelopeVersion: number;

  aad: {
    itemKey: string;
    payload: string;
  };
}

export interface EncryptedVaultItem {
  id: string;
  vaultId: string;

  revisionNumber: number;

  payloadVersion: number;
  ciphertextVersion: number;

  itemKeyVersion: number;
  vaultKeyVersion: number;

  envelopeVersion: number;

  itemKeyEnvelope: string;
  ciphertext: string;

  aad: {
    itemKey: string;
    payload: string;
  };

  createdAt: string;
  updatedAt: string;

  deletedAt: string | null;
}

interface CreateEncryptedVaultItemRequest {
  itemId: string;

  revisionNumber: number;

  payloadVersion: number;
  ciphertextVersion: number;

  itemKeyVersion: number;
  vaultKeyVersion: number;

  envelopeVersion: number;

  itemKeyEnvelope: string;
  ciphertext: string;
}

export interface CreatedVaultItem {
  id: string;
  vaultId: string;

  revisionNumber: number;

  createdAt: string;
}

export async function reserveVaultItem(vaultId: string): Promise<VaultItemReservation> {
  return apiRequest<VaultItemReservation>(`/api/v1/vaults/${vaultId}/items/options`, {
    method: 'POST',
    body: JSON.stringify({}),
  });
}

export async function createEncryptedVaultItem(
  vaultId: string,
  body: CreateEncryptedVaultItemRequest,
): Promise<CreatedVaultItem> {
  return apiRequest<CreatedVaultItem>(`/api/v1/vaults/${vaultId}/items`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export async function listEncryptedVaultItems(vaultId: string): Promise<EncryptedVaultItem[]> {
  const items: EncryptedVaultItem[] = [];

  let cursor: string | undefined;

  while (true) {
    const page = await listEncryptedVaultItemPage(vaultId, false, cursor);

    items.push(...page.items);

    if (!page.page.hasMore || !page.page.nextCursor) {
      break;
    }

    cursor = page.page.nextCursor;
  }

  return items;
}

export async function getEncryptedVaultItem(
  vaultId: string,
  itemId: string,
): Promise<EncryptedVaultItem> {
  return apiRequest<EncryptedVaultItem>(`/api/v1/vaults/${vaultId}/items/${itemId}`);
}

export interface VaultItemUpdateOptions {
  vaultId: string;
  itemId: string;

  expectedRevisionNumber: number;
  revisionNumber: number;

  payloadVersion: number;
  ciphertextVersion: number;

  itemKeyVersion: number;
  vaultKeyVersion: number;

  envelopeVersion: number;

  aad: {
    itemKey: string;
    payload: string;
  };
}

interface CreateEncryptedVaultItemRevisionRequest {
  expectedRevisionNumber: number;
  revisionNumber: number;

  payloadVersion: number;
  ciphertextVersion: number;

  itemKeyVersion: number;
  vaultKeyVersion: number;

  envelopeVersion: number;

  itemKeyEnvelope: string;
  ciphertext: string;
}

export async function getVaultItemUpdateOptions(
  vaultId: string,
  itemId: string,
  expectedRevisionNumber: number,
): Promise<VaultItemUpdateOptions> {
  return apiRequest<VaultItemUpdateOptions>(
    `/api/v1/vaults/${vaultId}/items/${itemId}/revisions/options`,
    {
      method: 'POST',

      body: JSON.stringify({
        expectedRevisionNumber,
      }),
    },
  );
}

export async function createEncryptedVaultItemRevision(
  vaultId: string,
  itemId: string,
  body: CreateEncryptedVaultItemRevisionRequest,
): Promise<CreatedVaultItem> {
  return apiRequest<CreatedVaultItem>(`/api/v1/vaults/${vaultId}/items/${itemId}/revisions`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export interface DeletedVaultItem {
  id: string;
  vaultId: string;

  revisionNumber: number;

  deletedAt: string;
}

export async function deleteEncryptedVaultItem(
  vaultId: string,
  itemId: string,
  expectedRevisionNumber: number,
): Promise<DeletedVaultItem> {
  return apiRequest<DeletedVaultItem>(`/api/v1/vaults/${vaultId}/items/${itemId}`, {
    method: 'DELETE',

    body: JSON.stringify({
      expectedRevisionNumber,
    }),
  });
}

export interface EncryptedVaultItem {
  id: string;
  vaultId: string;

  revisionNumber: number;

  payloadVersion: number;
  ciphertextVersion: number;

  itemKeyVersion: number;
  vaultKeyVersion: number;

  envelopeVersion: number;

  itemKeyEnvelope: string;
  ciphertext: string;

  aad: {
    itemKey: string;
    payload: string;
  };

  createdAt: string;

  deletedAt: string | null;
}

export interface RestoredVaultItem {
  id: string;
  vaultId: string;

  revisionNumber: number;

  restoredAt: string | null;
}

export async function listAllEncryptedVaultItems(vaultId: string): Promise<EncryptedVaultItem[]> {
  const items: EncryptedVaultItem[] = [];

  let cursor: string | undefined;

  while (true) {
    const page = await listEncryptedVaultItemPage(vaultId, true, cursor);

    items.push(...page.items);

    if (!page.page.hasMore || !page.page.nextCursor) {
      break;
    }

    cursor = page.page.nextCursor;
  }

  return items;
}

export async function restoreEncryptedVaultItem(
  vaultId: string,
  itemId: string,
  expectedRevisionNumber: number,
): Promise<RestoredVaultItem> {
  return apiRequest<RestoredVaultItem>(`/api/v1/vaults/${vaultId}/items/${itemId}/restore`, {
    method: 'POST',

    body: JSON.stringify({
      expectedRevisionNumber,
    }),
  });
}

export interface VaultItemPage {
  items: EncryptedVaultItem[];

  page: {
    hasMore: boolean;
    nextCursor: string | null;
    snapshotAt: string;
  };
}

export type VaultItemChangeKind = 'CREATED' | 'UPDATED' | 'DELETED' | 'RESTORED' | 'SNAPSHOT';

export interface VaultItemSyncChange {
  changeId: string;

  version: string;
  kind: VaultItemChangeKind;

  itemId: string;
  revisionNumber: number;

  deletedAt: string | null;
  changedAt: string;

  item: EncryptedVaultItem | null;
}

export interface VaultItemSyncResponse {
  changes: VaultItemSyncChange[];

  sync: {
    hasMore: boolean;
    nextCursor: string;
  };
}

async function listEncryptedVaultItemPage(
  vaultId: string,
  includeDeleted: boolean,
  cursor?: string,
): Promise<VaultItemPage> {
  const query = new URLSearchParams();

  query.set('includeDeleted', includeDeleted ? 'true' : 'false');

  query.set('limit', '100');

  if (cursor) {
    query.set('cursor', cursor);
  }

  return apiRequest<VaultItemPage>(`/api/v1/vaults/${vaultId}/items?${query.toString()}`);
}

export async function syncEncryptedVaultItems(
  vaultId: string,
  cursor?: string,
): Promise<VaultItemSyncResponse> {
  const query = new URLSearchParams();

  query.set('limit', '200');

  if (cursor) {
    query.set('cursor', cursor);
  }

  return apiRequest<VaultItemSyncResponse>(
    `/api/v1/vaults/${vaultId}/items/sync?${query.toString()}`,
  );
}
