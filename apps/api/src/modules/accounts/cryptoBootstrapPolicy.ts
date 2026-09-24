export const CRYPTO_PROTOCOL_VERSION = 1;
export const KDF_PROFILE_VERSION = 1;
export const KEY_ENVELOPE_VERSION = 1;

export const ARGON2_MEMORY_KIB = 19 * 1024;
export const ARGON2_ITERATIONS = 2;
export const ARGON2_PARALLELISM = 1;

export const KDF_SALT_BYTES = 16;
export const KEY_ENVELOPE_BYTES = 61;

export function rootKeyAad(cryptoProfileId: string): string {
  return `pm:v1:ark:crypto-profile:${cryptoProfileId}:key-version:1`;
}

export function recoveryRootKeyAad(cryptoProfileId: string): string {
  return `pm:v1:recovery-ark:crypto-profile:${cryptoProfileId}:key-version:1`;
}

export function vaultKeyAad(vaultId: string): string {
  return `pm:v1:pvk:vault:${vaultId}:key-version:1`;
}
