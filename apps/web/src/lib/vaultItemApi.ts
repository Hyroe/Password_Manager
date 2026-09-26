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
  const response = await apiRequest<{
    items: EncryptedVaultItem[];
  }>(`/api/v1/vaults/${vaultId}/items`);

  return response.items;
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
  const response = await apiRequest<{
    items: EncryptedVaultItem[];
  }>(`/api/v1/vaults/${vaultId}/items?includeDeleted=true`);

  return response.items;
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
