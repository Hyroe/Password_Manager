import { describe, expect, it } from 'vitest';

import { deriveCsrfToken, verifyCsrfToken } from './csrfToken.js';

describe('CSRF token derivation', () => {
  it('derives a stable token for one session', () => {
    const sessionToken = 'session-token-a';

    expect(deriveCsrfToken(sessionToken)).toBe(deriveCsrfToken(sessionToken));
  });

  it('binds the token to the session', () => {
    expect(deriveCsrfToken('session-token-a')).not.toBe(deriveCsrfToken('session-token-b'));
  });

  it('does not expose the session token', () => {
    const sessionToken = 'session-token-a';

    const csrfToken = deriveCsrfToken(sessionToken);

    expect(csrfToken).not.toContain(sessionToken);
  });

  it('verifies the correct session token pair', () => {
    const sessionToken = 'session-token-a';

    const csrfToken = deriveCsrfToken(sessionToken);

    expect(verifyCsrfToken(sessionToken, csrfToken)).toBe(true);
  });

  it('rejects a token from another session', () => {
    const csrfToken = deriveCsrfToken('session-token-a');

    expect(verifyCsrfToken('session-token-b', csrfToken)).toBe(false);
  });

  it('rejects malformed tokens', () => {
    expect(verifyCsrfToken('session-token-a', 'invalid')).toBe(false);
  });
});
