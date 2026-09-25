import type { CookieOptions } from 'express';

export const SESSION_IDLE_TTL_MS = 30 * 60 * 1000;

export const SESSION_ABSOLUTE_TTL_MS = 12 * 60 * 60 * 1000;

export function sessionCookieName(): string {
  return process.env.NODE_ENV === 'production' ? '__Host-pm_session' : 'pm_session';
}

export function sessionCookieOptions(): CookieOptions {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: SESSION_ABSOLUTE_TTL_MS,
  };
}
