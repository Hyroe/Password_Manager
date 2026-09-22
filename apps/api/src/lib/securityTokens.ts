import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export function generateSecurityToken(): string {
  return randomBytes(32).toString('base64url');
}

export function hashSecurityToken(token: string): Buffer {
  return createHash('sha256').update(token).digest();
}

export function verifySecurityToken(token: string, expectedHash: Uint8Array): boolean {
  const actualHash = hashSecurityToken(token);
  const storedHash = Buffer.from(expectedHash);

  if (actualHash.length !== storedHash.length) {
    return false;
  }

  return timingSafeEqual(actualHash, storedHash);
}
