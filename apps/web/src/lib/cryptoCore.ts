import initCryptoWasm, {
  create_account_bootstrap,
  type AccountBootstrapResult,
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

export type { AccountBootstrapResult };
