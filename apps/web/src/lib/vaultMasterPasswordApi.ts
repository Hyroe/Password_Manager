import { apiRequest } from './api';

export interface CompleteMasterPasswordChangeInput {
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
}

export async function completeMasterPasswordChange(
  input: CompleteMasterPasswordChangeInput,
): Promise<void> {
  await apiRequest<void>('/api/v1/crypto/master-password/change', {
    method: 'POST',

    body: JSON.stringify(input),
  });
}
