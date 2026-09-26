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
