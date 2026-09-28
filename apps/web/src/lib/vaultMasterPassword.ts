import {
  changeMasterPassword,
  getSupportedCryptoPolicy,
  type MasterPasswordChangeResult,
} from './cryptoCore';

import { base64UrlToBytes, bytesToBase64Url, wipeBytes } from './encoding';

import type { RecoveryKit } from './recoveryKit';

import { completeMasterPasswordChange } from './vaultMasterPasswordApi';

import { getVaultUnlockMaterial } from './vaultUnlockApi';

interface ChangeVaultMasterPasswordInput {
  currentMasterPassword: string;
  newMasterPassword: string;

  recoveryKit: RecoveryKit;

  authenticatedEmail: string;
}

export async function changeVaultMasterPassword(
  input: ChangeVaultMasterPasswordInput,
): Promise<void> {
  /*
   * The Account Secret required for MPK
   * derivation is stored in the Recovery Kit.
   *
   * It must belong to the authenticated account.
   */
  if (
    input.recoveryKit.account.email.trim().toLowerCase() !==
    input.authenticatedEmail.trim().toLowerCase()
  ) {
    throw new Error('Recovery Kit belongs to a different account.');
  }

  const material = await getVaultUnlockMaterial();

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

  let accountSecret: Uint8Array | undefined;

  let currentKdfSalt: Uint8Array | undefined;

  let currentRootKeyEnvelope: Uint8Array | undefined;

  let rootKeyAad: Uint8Array | undefined;

  let newKdfSalt: Uint8Array | undefined;

  let newRootKeyEnvelope: Uint8Array | undefined;

  let changeResult: MasterPasswordChangeResult | undefined;

  const encoder = new TextEncoder();

  try {
    accountSecret = base64UrlToBytes(input.recoveryKit.secrets.accountSecret);

    if (accountSecret.length !== 32) {
      throw new Error('Recovery Kit Account Secret is invalid.');
    }

    currentKdfSalt = base64UrlToBytes(material.kdf.salt);

    if (currentKdfSalt.length !== 16) {
      throw new Error('Account KDF salt is invalid.');
    }

    currentRootKeyEnvelope = base64UrlToBytes(material.rootKey.envelope);

    if (currentRootKeyEnvelope.length !== 61) {
      throw new Error('Account root key envelope is invalid.');
    }

    rootKeyAad = encoder.encode(material.rootKey.aad);

    /*
     * Everything sensitive below happens
     * locally inside the client/WASM.
     *
     * Current Master Password + Account Secret
     * + current salt
     *      ↓
     * current MKEK
     *      ↓
     * unwrap existing ARK
     *
     * New Master Password + same Account Secret
     * + fresh salt
     *      ↓
     * new MKEK
     *      ↓
     * wrap SAME ARK
     */
    changeResult = await changeMasterPassword({
      currentMasterPassword: input.currentMasterPassword,

      newMasterPassword: input.newMasterPassword,

      accountSecret,

      currentKdfSalt,

      currentRootKeyEnvelope,

      rootKeyAad,
    });

    const resultPolicyMatches =
      changeResult.protocol_version === material.protocolVersion &&
      changeResult.kdf_profile_version === material.kdf.profileVersion &&
      changeResult.argon2_memory_kib === material.kdf.memoryKib &&
      changeResult.argon2_iterations === material.kdf.iterations &&
      changeResult.argon2_parallelism === material.kdf.parallelism;

    if (!resultPolicyMatches) {
      throw new Error('Changed cryptographic material does not match the account policy.');
    }

    newKdfSalt = changeResult.kdf_salt();

    newRootKeyEnvelope = changeResult.root_key_envelope();

    if (newKdfSalt.length !== 16) {
      throw new Error('Changed KDF salt is invalid.');
    }

    if (newRootKeyEnvelope.length !== 61) {
      throw new Error('Changed root key envelope is invalid.');
    }

    /*
     * Only new encrypted material and protocol
     * metadata leave the client.
     *
     * Neither Master Password nor Account Secret
     * nor plaintext ARK are sent to the server.
     */
    await completeMasterPasswordChange({
      protocolVersion: changeResult.protocol_version,

      kdf: {
        algorithm: 'ARGON2ID',

        profileVersion: changeResult.kdf_profile_version,

        memoryKib: changeResult.argon2_memory_kib,

        iterations: changeResult.argon2_iterations,

        parallelism: changeResult.argon2_parallelism,

        salt: bytesToBase64Url(newKdfSalt),
      },

      rootKey: {
        keyVersion: material.rootKey.keyVersion,

        envelopeVersion: material.rootKey.envelopeVersion,

        expectedUpdatedAt: material.rootKey.updatedAt,

        envelope: bytesToBase64Url(newRootKeyEnvelope),
      },
    });
  } catch (error) {
    if (error instanceof Error) {
      throw error;
    }

    throw new Error('Master Password change failed.', {
      cause: error,
    });
  } finally {
    if (newKdfSalt) {
      wipeBytes(newKdfSalt);
    }

    if (newRootKeyEnvelope) {
      wipeBytes(newRootKeyEnvelope);
    }

    if (accountSecret) {
      wipeBytes(accountSecret);
    }

    if (currentKdfSalt) {
      wipeBytes(currentKdfSalt);
    }

    if (currentRootKeyEnvelope) {
      wipeBytes(currentRootKeyEnvelope);
    }

    if (rootKeyAad) {
      wipeBytes(rootKeyAad);
    }

    if (changeResult) {
      changeResult.clear();
      changeResult.free();
    }
  }
}
