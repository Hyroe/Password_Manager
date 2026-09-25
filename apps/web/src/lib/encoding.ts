export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function base64UrlToBytes(value: string): Uint8Array {
  if (!value || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('Invalid Base64URL value.');
  }

  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');

  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);

  const binary = atob(padded);

  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  if (bytesToBase64Url(bytes) !== value) {
    throw new Error('Non-canonical Base64URL value.');
  }

  return bytes;
}

export function wipeBytes(bytes: Uint8Array | undefined): void {
  bytes?.fill(0);
}
