import type { UnlockedVault } from './cryptoCore';

import {
  decryptLoginItem,
  encryptLoginItem,
  type LoginItemDraft,
  type LoginItemPayload,
} from './cryptoCore';

import { base64UrlToBytes, bytesToBase64Url, wipeBytes } from './encoding';

import {
  ITEM_CIPHERTEXT_VERSION,
  ITEM_KEY_ENVELOPE_BYTES,
  ITEM_KEY_ENVELOPE_VERSION,
  ITEM_KEY_VERSION,
  ITEM_PAYLOAD_VERSION,
  MIN_ITEM_CIPHERTEXT_BYTES,
  itemKeyAad,
  itemPayloadAad,
} from './vaultItemCryptoContext';

import {
  createEncryptedVaultItem,
  getEncryptedVaultItem,
  listEncryptedVaultItems,
  reserveVaultItem,
  type CreatedVaultItem,
  type EncryptedVaultItem,
  type VaultItemReservation,
} from './vaultItemApi';

function expectedAad(item: {
  vaultId: string;
  itemId: string;

  revisionNumber: number;

  itemKeyVersion: number;
  vaultKeyVersion: number;
}) {
  return {
    itemKey: itemKeyAad(item.vaultId, item.itemId, item.revisionNumber, item.vaultKeyVersion),

    payload: itemPayloadAad(item.vaultId, item.itemId, item.revisionNumber, item.itemKeyVersion),
  };
}

function validateReservation(vaultId: string, reservation: VaultItemReservation) {
  if (
    reservation.vaultId !== vaultId ||
    reservation.revisionNumber !== 1 ||
    reservation.payloadVersion !== ITEM_PAYLOAD_VERSION ||
    reservation.ciphertextVersion !== ITEM_CIPHERTEXT_VERSION ||
    reservation.itemKeyVersion !== ITEM_KEY_VERSION ||
    reservation.envelopeVersion !== ITEM_KEY_ENVELOPE_VERSION
  ) {
    throw new Error('Unsupported vault item crypto context.');
  }

  const aad = expectedAad({
    vaultId: reservation.vaultId,

    itemId: reservation.itemId,

    revisionNumber: reservation.revisionNumber,

    itemKeyVersion: reservation.itemKeyVersion,

    vaultKeyVersion: reservation.vaultKeyVersion,
  });

  if (reservation.aad.itemKey !== aad.itemKey || reservation.aad.payload !== aad.payload) {
    throw new Error('Invalid vault item crypto context.');
  }

  return aad;
}

function validateEncryptedItem(expectedVaultId: string, item: EncryptedVaultItem) {
  if (
    item.vaultId !== expectedVaultId ||
    item.payloadVersion !== ITEM_PAYLOAD_VERSION ||
    item.ciphertextVersion !== ITEM_CIPHERTEXT_VERSION ||
    item.itemKeyVersion !== ITEM_KEY_VERSION ||
    item.envelopeVersion !== ITEM_KEY_ENVELOPE_VERSION
  ) {
    throw new Error('Unsupported encrypted vault item.');
  }

  const aad = expectedAad({
    vaultId: item.vaultId,
    itemId: item.id,

    revisionNumber: item.revisionNumber,

    itemKeyVersion: item.itemKeyVersion,

    vaultKeyVersion: item.vaultKeyVersion,
  });

  if (item.aad.itemKey !== aad.itemKey || item.aad.payload !== aad.payload) {
    throw new Error('Invalid encrypted item context.');
  }

  return aad;
}

export async function createLoginVaultItem(
  vault: UnlockedVault,
  vaultId: string,
  draft: LoginItemDraft,
): Promise<CreatedVaultItem> {
  const reservation = await reserveVaultItem(vaultId);

  const aad = validateReservation(vaultId, reservation);

  const encrypted = await encryptLoginItem(vault, draft, aad.itemKey, aad.payload);

  try {
    if (
      encrypted.payloadVersion !== reservation.payloadVersion ||
      encrypted.ciphertextVersion !== reservation.ciphertextVersion
    ) {
      throw new Error('Crypto output version mismatch.');
    }

    if (encrypted.itemKeyEnvelope.length !== ITEM_KEY_ENVELOPE_BYTES) {
      throw new Error('Invalid encrypted item key.');
    }

    return await createEncryptedVaultItem(vaultId, {
      itemId: reservation.itemId,

      revisionNumber: reservation.revisionNumber,

      payloadVersion: encrypted.payloadVersion,

      ciphertextVersion: encrypted.ciphertextVersion,

      itemKeyVersion: reservation.itemKeyVersion,

      vaultKeyVersion: reservation.vaultKeyVersion,

      envelopeVersion: reservation.envelopeVersion,

      itemKeyEnvelope: bytesToBase64Url(encrypted.itemKeyEnvelope),

      ciphertext: bytesToBase64Url(encrypted.ciphertext),
    });
  } finally {
    wipeBytes(encrypted.itemKeyEnvelope);

    wipeBytes(encrypted.ciphertext);
  }
}

export async function listVaultItems(vaultId: string): Promise<EncryptedVaultItem[]> {
  return listEncryptedVaultItems(vaultId);
}

export async function decryptStoredLoginItem(
  vault: UnlockedVault,
  vaultId: string,
  item: EncryptedVaultItem,
): Promise<LoginItemPayload> {
  const aad = validateEncryptedItem(vaultId, item);

  const itemKeyEnvelope = base64UrlToBytes(item.itemKeyEnvelope);

  const ciphertext = base64UrlToBytes(item.ciphertext);

  try {
    if (
      itemKeyEnvelope.length !== ITEM_KEY_ENVELOPE_BYTES ||
      itemKeyEnvelope[0] !== item.envelopeVersion
    ) {
      throw new Error('Invalid encrypted item key.');
    }

    if (ciphertext.length < MIN_ITEM_CIPHERTEXT_BYTES || ciphertext[0] !== item.ciphertextVersion) {
      throw new Error('Invalid encrypted item payload.');
    }

    return await decryptLoginItem({
      vault,

      itemKeyEnvelope,
      itemKeyAad: aad.itemKey,

      ciphertext,
      payloadAad: aad.payload,
    });
  } finally {
    wipeBytes(itemKeyEnvelope);
    wipeBytes(ciphertext);
  }
}

export async function loadAndDecryptLoginItem(
  vault: UnlockedVault,
  vaultId: string,
  itemId: string,
): Promise<LoginItemPayload> {
  const item = await getEncryptedVaultItem(vaultId, itemId);

  if (item.id !== itemId) {
    throw new Error('Unexpected vault item response.');
  }

  return decryptStoredLoginItem(vault, vaultId, item);
}
