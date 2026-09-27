export const VAULT_ITEM_RESERVATION_TTL_MS = 60 * 60 * 1000;

export function getVaultItemReservationExpiresAt(createdAt: Date): Date {
  return new Date(createdAt.getTime() + VAULT_ITEM_RESERVATION_TTL_MS);
}

export function isVaultItemReservationExpired(createdAt: Date, now = new Date()): boolean {
  return getVaultItemReservationExpiresAt(createdAt).getTime() <= now.getTime();
}
