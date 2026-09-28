import initCryptoWasm, {
  create_account_bootstrap,
  crypto_argon2_iterations,
  crypto_argon2_memory_kib,
  crypto_argon2_parallelism,
  crypto_kdf_profile_version,
  crypto_protocol_version,
  recover_master_password,
  unlock_personal_vault,
  type AccountBootstrapResult,
  type MasterPasswordRecoveryResult,
  type UnlockedVault,
} from '@pm/crypto-core';

import {
  decrypt_login_item,
  encrypt_login_item,
  type EncryptedItemRevision,
} from '@pm/crypto-core';

let initialization: Promise<void> | undefined;

export async function initializeCryptoCore(): Promise<void> {
  if (!initialization) {
    initialization = initCryptoWasm()
      .then(() => undefined)
      .catch((error: unknown) => {
        initialization = undefined;
        throw error;
      });
  }

  await initialization;
}

interface CreateAccountBootstrapInput {
  masterPassword: string;
  rootKeyAad: Uint8Array;
  recoveryRootKeyAad: Uint8Array;
  vaultKeyAad: Uint8Array;
}

export async function createAccountBootstrap(
  input: CreateAccountBootstrapInput,
): Promise<AccountBootstrapResult> {
  await initializeCryptoCore();

  return create_account_bootstrap(
    input.masterPassword,
    input.rootKeyAad,
    input.recoveryRootKeyAad,
    input.vaultKeyAad,
  );
}

export interface SupportedCryptoPolicy {
  protocolVersion: number;
  kdfProfileVersion: number;

  memoryKib: number;
  iterations: number;
  parallelism: number;
}

export async function getSupportedCryptoPolicy(): Promise<SupportedCryptoPolicy> {
  await initializeCryptoCore();

  return {
    protocolVersion: crypto_protocol_version(),

    kdfProfileVersion: crypto_kdf_profile_version(),

    memoryKib: crypto_argon2_memory_kib(),

    iterations: crypto_argon2_iterations(),

    parallelism: crypto_argon2_parallelism(),
  };
}

interface UnlockPersonalVaultInput {
  masterPassword: string;

  accountSecret: Uint8Array;
  kdfSalt: Uint8Array;

  rootKeyEnvelope: Uint8Array;
  rootKeyAad: Uint8Array;

  vaultKeyEnvelope: Uint8Array;
  vaultKeyAad: Uint8Array;
}

export async function unlockPersonalVault(input: UnlockPersonalVaultInput): Promise<UnlockedVault> {
  await initializeCryptoCore();

  return unlock_personal_vault(
    input.masterPassword,

    input.accountSecret,
    input.kdfSalt,

    input.rootKeyEnvelope,
    input.rootKeyAad,

    input.vaultKeyEnvelope,
    input.vaultKeyAad,
  );
}

interface RecoverMasterPasswordInput {
  newMasterPassword: string;

  accountSecret: Uint8Array;
  recoveryKey: Uint8Array;

  recoveryRootKeyEnvelope: Uint8Array;
  recoveryRootKeyAad: Uint8Array;

  rootKeyAad: Uint8Array;
}

export async function recoverMasterPassword(
  input: RecoverMasterPasswordInput,
): Promise<MasterPasswordRecoveryResult> {
  await initializeCryptoCore();

  return recover_master_password(
    input.newMasterPassword,

    input.accountSecret,
    input.recoveryKey,

    input.recoveryRootKeyEnvelope,
    input.recoveryRootKeyAad,

    input.rootKeyAad,
  );
}

export interface LoginItemDraft {
  name: string;
  username: string;
  password: string;
  urls: string[];
  notes: string;
}

export interface LoginItemPayload extends LoginItemDraft {
  schemaVersion: 1;
  itemType: 'LOGIN';
}

export interface EncryptedLoginItem {
  payloadVersion: number;
  ciphertextVersion: number;

  itemKeyEnvelope: Uint8Array;
  ciphertext: Uint8Array;
}

function isLoginItemPayload(value: unknown): value is LoginItemPayload {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  const payload = value as Record<string, unknown>;

  return (
    payload.schemaVersion === 1 &&
    payload.itemType === 'LOGIN' &&
    typeof payload.name === 'string' &&
    typeof payload.username === 'string' &&
    typeof payload.password === 'string' &&
    Array.isArray(payload.urls) &&
    payload.urls.every((url) => typeof url === 'string') &&
    typeof payload.notes === 'string'
  );
}

export async function encryptLoginItem(
  vault: UnlockedVault,
  input: LoginItemDraft,
  itemKeyAad: string,
  payloadAad: string,
): Promise<EncryptedLoginItem> {
  await initializeCryptoCore();

  const encoder = new TextEncoder();

  const itemKeyAadBytes = encoder.encode(itemKeyAad);

  const payloadAadBytes = encoder.encode(payloadAad);

  let encrypted: EncryptedItemRevision | undefined;

  try {
    encrypted = encrypt_login_item(vault, input, itemKeyAadBytes, payloadAadBytes);

    return {
      payloadVersion: encrypted.payload_version,

      ciphertextVersion: encrypted.ciphertext_version,

      itemKeyEnvelope: encrypted.item_key_envelope(),

      ciphertext: encrypted.ciphertext(),
    };
  } finally {
    itemKeyAadBytes.fill(0);
    payloadAadBytes.fill(0);

    if (encrypted) {
      encrypted.clear();
      encrypted.free();
    }
  }
}

interface DecryptLoginItemInput {
  vault: UnlockedVault;

  itemKeyEnvelope: Uint8Array;
  itemKeyAad: string;

  ciphertext: Uint8Array;
  payloadAad: string;
}

export async function decryptLoginItem(input: DecryptLoginItemInput): Promise<LoginItemPayload> {
  await initializeCryptoCore();

  const encoder = new TextEncoder();

  const itemKeyAadBytes = encoder.encode(input.itemKeyAad);

  const payloadAadBytes = encoder.encode(input.payloadAad);

  try {
    const result = decrypt_login_item(
      input.vault,

      input.itemKeyEnvelope,
      itemKeyAadBytes,

      input.ciphertext,
      payloadAadBytes,
    ) as unknown;

    if (!isLoginItemPayload(result)) {
      throw new Error('Invalid decrypted LOGIN payload.');
    }

    return result;
  } finally {
    itemKeyAadBytes.fill(0);
    payloadAadBytes.fill(0);
  }
}

export type { AccountBootstrapResult, MasterPasswordRecoveryResult, UnlockedVault };
