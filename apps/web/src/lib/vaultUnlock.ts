import { getSupportedCryptoPolicy, unlockPersonalVault, type UnlockedVault } from './cryptoCore';

import { base64UrlToBytes, wipeBytes } from './encoding';

import type { RecoveryKit } from './recoveryKit';

import { getVaultUnlockMaterial } from './vaultUnlockApi';

interface UnlockVaultInput {
  masterPassword: string;
  recoveryKit: RecoveryKit;

  authenticatedEmail: string;
}

export async function unlockVault(input: UnlockVaultInput): Promise<UnlockedVault> {
  const material = await getVaultUnlockMaterial();

  /*
   * Prevent accidentally using a Recovery
   * Kit belonging to another account.
   */
  if (
    input.recoveryKit.account.email.trim().toLowerCase() !==
    input.authenticatedEmail.trim().toLowerCase()
  ) {
    throw new Error('Recovery Kit belongs to a different account.');
  }

  if (input.recoveryKit.account.cryptoProfileId !== material.cryptoProfileId) {
    throw new Error('Recovery Kit does not match this cryptographic profile.');
  }

  if (input.recoveryKit.account.vaultId !== material.vault.id) {
    throw new Error('Recovery Kit does not match this vault.');
  }

  const supported = await getSupportedCryptoPolicy();

  const policyMatches =
    material.protocolVersion === supported.protocolVersion &&
    material.kdf.profileVersion === supported.kdfProfileVersion &&
    material.kdf.memoryKib === supported.memoryKib &&
    material.kdf.iterations === supported.iterations &&
    material.kdf.parallelism === supported.parallelism;

  if (!policyMatches) {
    throw new Error('This client does not support the account cryptographic profile.');
  }

  if (
    input.recoveryKit.crypto.protocolVersion !== material.protocolVersion ||
    input.recoveryKit.crypto.kdfProfileVersion !== material.kdf.profileVersion
  ) {
    throw new Error('Recovery Kit cryptographic metadata does not match the account.');
  }

  const accountSecret = base64UrlToBytes(input.recoveryKit.secrets.accountSecret);

  if (accountSecret.length !== 32) {
    accountSecret.fill(0);

    throw new Error('Recovery Kit Account Secret is invalid.');
  }

  const kdfSalt = base64UrlToBytes(material.kdf.salt);

  const rootEnvelope = base64UrlToBytes(material.rootKey.envelope);

  const vaultEnvelope = base64UrlToBytes(material.vault.envelope);

  const encoder = new TextEncoder();

  const rootAad = encoder.encode(material.rootKey.aad);

  const vaultAad = encoder.encode(material.vault.aad);

  try {
    return await unlockPersonalVault({
      masterPassword: input.masterPassword,

      accountSecret,
      kdfSalt,

      rootKeyEnvelope: rootEnvelope,

      rootKeyAad: rootAad,

      vaultKeyEnvelope: vaultEnvelope,

      vaultKeyAad: vaultAad,
    });
  } catch (error) {
    throw new Error('Vault could not be unlocked.', {
      cause: error,
    });
  } finally {
    wipeBytes(accountSecret);
    wipeBytes(kdfSalt);

    wipeBytes(rootEnvelope);
    wipeBytes(vaultEnvelope);

    wipeBytes(rootAad);
    wipeBytes(vaultAad);
  }
}
