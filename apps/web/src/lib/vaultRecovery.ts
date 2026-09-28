import {
  getSupportedCryptoPolicy,
  recoverMasterPassword,
  type MasterPasswordRecoveryResult,
} from './cryptoCore';

import { base64UrlToBytes, bytesToBase64Url, wipeBytes } from './encoding';

import type { RecoveryKit } from './recoveryKit';

import {
  completeMasterPasswordRecovery,
  getMasterPasswordRecoveryMaterial,
} from './vaultRecoveryApi';

interface RecoverVaultMasterPasswordInput {
  newMasterPassword: string;

  recoveryKit: RecoveryKit;

  authenticatedEmail: string;
}

export async function recoverVaultMasterPassword(
  input: RecoverVaultMasterPasswordInput,
): Promise<void> {
  /*
   * Recovery still requires an authenticated
   * account. The Recovery Kit must belong to
   * that same identity.
   */
  if (
    input.recoveryKit.account.email.trim().toLowerCase() !==
    input.authenticatedEmail.trim().toLowerCase()
  ) {
    throw new Error('Recovery Kit belongs to a different account.');
  }

  const material = await getMasterPasswordRecoveryMaterial();

  if (input.recoveryKit.account.cryptoProfileId !== material.cryptoProfileId) {
    throw new Error('Recovery Kit does not match this cryptographic profile.');
  }

  /*
   * Make sure this client understands the
   * server-side crypto profile before using
   * any Recovery Kit secret.
   */
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

  /*
   * The recovery envelope must protect the
   * same ARK version that the new Master
   * Password envelope will replace.
   */
  if (material.recoveryRootKey.rootKeyVersion !== material.rootKey.keyVersion) {
    throw new Error('Account recovery cryptographic state is inconsistent.');
  }

  let accountSecret: Uint8Array | undefined;

  let recoveryKey: Uint8Array | undefined;

  let recoveryRootKeyEnvelope: Uint8Array | undefined;

  let recoveryRootKeyAad: Uint8Array | undefined;

  let rootKeyAad: Uint8Array | undefined;

  let newKdfSalt: Uint8Array | undefined;

  let newRootKeyEnvelope: Uint8Array | undefined;

  let recoveryResult: MasterPasswordRecoveryResult | undefined;

  const encoder = new TextEncoder();

  try {
    accountSecret = base64UrlToBytes(input.recoveryKit.secrets.accountSecret);

    if (accountSecret.length !== 32) {
      throw new Error('Recovery Kit Account Secret is invalid.');
    }

    recoveryKey = base64UrlToBytes(input.recoveryKit.secrets.recoveryKey);

    if (recoveryKey.length !== 32) {
      throw new Error('Recovery Kit Recovery Key is invalid.');
    }

    recoveryRootKeyEnvelope = base64UrlToBytes(material.recoveryRootKey.envelope);

    recoveryRootKeyAad = encoder.encode(material.recoveryRootKey.aad);

    rootKeyAad = encoder.encode(material.rootKey.aad);

    /*
     * Everything below happens locally.
     *
     * WASM:
     * Recovery Key -> Recovery KEK
     * Recovery KEK -> existing ARK
     * New Master Password + Account Secret
     * -> new MPK -> new MKEK
     * new MKEK -> wraps the SAME ARK
     */
    recoveryResult = await recoverMasterPassword({
      newMasterPassword: input.newMasterPassword,

      accountSecret,
      recoveryKey,

      recoveryRootKeyEnvelope,
      recoveryRootKeyAad,

      rootKeyAad,
    });

    /*
     * Refuse to persist material created using
     * a crypto policy different from the one
     * agreed with the server.
     */
    const resultPolicyMatches =
      recoveryResult.protocol_version === material.protocolVersion &&
      recoveryResult.kdf_profile_version === material.kdf.profileVersion &&
      recoveryResult.argon2_memory_kib === material.kdf.memoryKib &&
      recoveryResult.argon2_iterations === material.kdf.iterations &&
      recoveryResult.argon2_parallelism === material.kdf.parallelism;

    if (!resultPolicyMatches) {
      throw new Error('Recovered cryptographic material does not match the account policy.');
    }

    newKdfSalt = recoveryResult.kdf_salt();

    newRootKeyEnvelope = recoveryResult.root_key_envelope();

    if (newKdfSalt.length !== 16) {
      throw new Error('Recovered KDF salt is invalid.');
    }

    if (newRootKeyEnvelope.length !== 61) {
      throw new Error('Recovered root key envelope is invalid.');
    }

    /*
     * The server stores only the fresh salt
     * and the newly wrapped ARK.
     *
     * Recovery Key, Account Secret and
     * plaintext ARK never leave this client.
     */
    await completeMasterPasswordRecovery({
      protocolVersion: recoveryResult.protocol_version,

      kdf: {
        algorithm: 'ARGON2ID',

        profileVersion: recoveryResult.kdf_profile_version,

        memoryKib: recoveryResult.argon2_memory_kib,

        iterations: recoveryResult.argon2_iterations,

        parallelism: recoveryResult.argon2_parallelism,

        salt: bytesToBase64Url(newKdfSalt),
      },

      rootKey: {
        keyVersion: material.rootKey.keyVersion,

        envelopeVersion: material.rootKey.envelopeVersion,

        expectedUpdatedAt: material.rootKey.updatedAt,

        envelope: bytesToBase64Url(newRootKeyEnvelope),
      },

      recovery: {
        recoveryVersion: material.recoveryRootKey.recoveryVersion,

        rootKeyVersion: material.recoveryRootKey.rootKeyVersion,
      },
    });
  } catch (error) {
    if (error instanceof Error) {
      throw error;
    }

    throw new Error('Master Password recovery failed.', {
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

    if (recoveryKey) {
      wipeBytes(recoveryKey);
    }

    if (recoveryRootKeyEnvelope) {
      wipeBytes(recoveryRootKeyEnvelope);
    }

    if (recoveryRootKeyAad) {
      wipeBytes(recoveryRootKeyAad);
    }

    if (rootKeyAad) {
      wipeBytes(rootKeyAad);
    }

    if (recoveryResult) {
      recoveryResult.clear();
      recoveryResult.free();
    }
  }
}
