import { apiRequest } from './api';

export interface VaultUnlockMaterial {
  protocolVersion: number;

  cryptoProfileId: string;

  kdf: {
    algorithm: 'ARGON2ID';

    profileVersion: number;

    memoryKib: number;
    iterations: number;
    parallelism: number;

    salt: string;
  };

  rootKey: {
    keyVersion: number;
    envelopeVersion: number;

    envelope: string;
    aad: string;
  };

  vault: {
    id: string;
    kind: 'PERSONAL';

    keyVersion: number;
    rootKeyVersion: number;

    envelopeVersion: number;

    envelope: string;
    aad: string;
  };
}

export async function getVaultUnlockMaterial(): Promise<VaultUnlockMaterial> {
  return apiRequest<VaultUnlockMaterial>('/api/v1/crypto/unlock');
}
