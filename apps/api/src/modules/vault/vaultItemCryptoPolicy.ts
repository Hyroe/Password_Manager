export const ITEM_PAYLOAD_VERSION = 1;

export const ITEM_CIPHERTEXT_VERSION = 1;

export const ITEM_KEY_VERSION = 1;

export const ITEM_KEY_ENVELOPE_VERSION = 1;

export const ITEM_KEY_ENVELOPE_BYTES = 61;

/*
 * AES-GCM payload format:
 *
 * 1 byte version
 * 12 byte nonce
 * ciphertext
 * 16 byte authentication tag
 */
export const MIN_ITEM_CIPHERTEXT_BYTES = 1 + 12 + 16;

/*
 * Rust currently accepts at most
 * 96 KiB serialized plaintext.
 */
export const MAX_ITEM_CIPHERTEXT_BYTES = 96 * 1024 + MIN_ITEM_CIPHERTEXT_BYTES;

export function itemKeyAad(
  vaultId: string,
  itemId: string,
  revisionNumber: number,
  vaultKeyVersion: number,
): string {
  return [
    'pm:v1:item-key',
    `vault:${vaultId}`,
    `item:${itemId}`,
    `revision:${revisionNumber}`,
    `vault-key-version:${vaultKeyVersion}`,
  ].join(':');
}

export function itemPayloadAad(
  vaultId: string,
  itemId: string,
  revisionNumber: number,
  itemKeyVersion: number,
): string {
  return [
    'pm:v1:item-payload',
    `vault:${vaultId}`,
    `item:${itemId}`,
    `revision:${revisionNumber}`,
    `item-key-version:${itemKeyVersion}`,
  ].join(':');
}
