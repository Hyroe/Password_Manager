import { apiRequest } from './api';

export interface MasterPasswordRecoveryMaterial {
  protocolVersion: number;

  cryptoProfileId: string;

  kdf: {
    algorithm: 'ARGON2ID';

    profileVersion: number;

    memoryKib: number;
    iterations: number;
    parallelism: number;
  };

  recoveryRootKey: {
    recoveryVersion: number;

    rootKeyVersion: number;

    envelopeVersion: number;

    envelope: string;
    aad: string;
  };

  rootKey: {
    keyVersion: number;

    envelopeVersion: number;

    updatedAt: string;

    aad: string;
  };
}

export interface CompleteMasterPasswordRecoveryInput {
  protocolVersion: number;

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

    expectedUpdatedAt: string;

    envelope: string;
  };

  recovery: {
    recoveryVersion: number;

    rootKeyVersion: number;
  };
}

export async function getMasterPasswordRecoveryMaterial(): Promise<MasterPasswordRecoveryMaterial> {
  return apiRequest<MasterPasswordRecoveryMaterial>('/api/v1/crypto/recovery');
}

export async function completeMasterPasswordRecovery(
  input: CompleteMasterPasswordRecoveryInput,
): Promise<void> {
  await apiRequest<void>('/api/v1/crypto/recovery/complete', {
    method: 'POST',

    body: JSON.stringify(input),
  });
}
