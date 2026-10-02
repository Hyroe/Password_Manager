import type { CookieOptions } from 'express';

export const SESSION_IDLE_TTL_MS = 30 * 60 * 1000;

export const SESSION_ABSOLUTE_TTL_MS = 12 * 60 * 60 * 1000;

export const SESSION_TOUCH_INTERVAL_MS = 5 * 60 * 1000;

import { getEnvironment } from './env.js';

export function sessionCookieName(): string {
  return isProduction() ? '__Host-pm_session' : 'pm_session';
}

function sessionCookieBaseOptions(): CookieOptions {
  return {
    httpOnly: true,

    secure: isProduction(),

    sameSite: 'strict',

    path: '/',
  };
}

function isProduction(): boolean {
  return getEnvironment().NODE_ENV === 'production';
}

export function sessionCookieOptions(): CookieOptions {
  return {
    ...sessionCookieBaseOptions(),
    maxAge: SESSION_ABSOLUTE_TTL_MS,
  };
}

export function sessionCookieClearOptions(): CookieOptions {
  return sessionCookieBaseOptions();
}
