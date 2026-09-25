import { describe, expect, it } from 'vitest';

import { base64UrlToBytes, bytesToBase64Url } from './encoding';

describe('Base64URL encoding', () => {
  it('round trips bytes canonically', () => {
    const original = new Uint8Array([0, 1, 2, 3, 250, 251, 252, 255]);

    const encoded = bytesToBase64Url(original);

    const decoded = base64UrlToBytes(encoded);

    expect(Array.from(decoded)).toEqual(Array.from(original));
  });

  it('rejects invalid characters', () => {
    expect(() => base64UrlToBytes('not+base64url')).toThrow();
  });
});
