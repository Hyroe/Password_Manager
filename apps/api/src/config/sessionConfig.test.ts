import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  SESSION_ABSOLUTE_TTL_MS,
  sessionCookieClearOptions,
  sessionCookieName,
  sessionCookieOptions,
} from './session.js';

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('session cookie policy', () => {
  it('uses the hardened __Host cookie in production', () => {
    vi.stubEnv('NODE_ENV', 'production');

    expect(sessionCookieName()).toBe('__Host-pm_session');

    const options = sessionCookieOptions();

    expect(options).toEqual({
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      path: '/',
      maxAge: SESSION_ABSOLUTE_TTL_MS,
    });

    expect('domain' in options).toBe(false);
  });

  it('uses a non-secure development cookie outside production', () => {
    vi.stubEnv('NODE_ENV', 'test');

    expect(sessionCookieName()).toBe('pm_session');

    expect(sessionCookieOptions()).toEqual({
      httpOnly: true,
      secure: false,
      sameSite: 'strict',
      path: '/',
      maxAge: SESSION_ABSOLUTE_TTL_MS,
    });
  });

  it('clears the cookie using the same security attributes', () => {
    vi.stubEnv('NODE_ENV', 'production');

    const options = sessionCookieClearOptions();

    expect(options).toEqual({
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      path: '/',
    });

    expect('domain' in options).toBe(false);
  });
});
