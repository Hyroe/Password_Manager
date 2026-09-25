import initCryptoWasm, {
  create_account_bootstrap,
  crypto_argon2_iterations,
  crypto_argon2_memory_kib,
  crypto_argon2_parallelism,
  crypto_kdf_profile_version,
  crypto_protocol_version,
  unlock_personal_vault,
  type AccountBootstrapResult,
  type UnlockedVault,
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

export type { AccountBootstrapResult, UnlockedVault };
