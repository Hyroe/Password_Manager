export function encodeBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

export function decodeCanonicalBase64UrlValue(value: string): Uint8Array<ArrayBuffer> {
  if (!value || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('INVALID_BASE64URL');
  }

  const decoded = Buffer.from(value, 'base64url');

  if (decoded.toString('base64url') !== value) {
    throw new Error('INVALID_BASE64URL');
  }

  return Uint8Array.from(decoded);
}
