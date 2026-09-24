export function decodeCanonicalBase64Url(
  value: string,
  expectedBytes: number,
): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('INVALID_CRYPTO_MATERIAL');
  }

  const decoded = Buffer.from(value, 'base64url');

  if (decoded.length !== expectedBytes) {
    throw new Error('INVALID_CRYPTO_MATERIAL');
  }

  if (decoded.toString('base64url') !== value) {
    throw new Error('INVALID_CRYPTO_MATERIAL');
  }

  return Uint8Array.from(decoded);
}
