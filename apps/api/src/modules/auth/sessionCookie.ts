import type { Request } from 'express';

import { sessionCookieName } from '../../config/session.js';

export function getSessionTokenFromRequest(req: Request): string | undefined {
  const cookieHeader = req.headers.cookie;

  if (!cookieHeader) {
    return undefined;
  }

  const targetName = sessionCookieName();

  for (const part of cookieHeader.split(';')) {
    const cookie = part.trim();

    const separatorIndex = cookie.indexOf('=');

    if (separatorIndex === -1) {
      continue;
    }

    const name = cookie.slice(0, separatorIndex);

    if (name !== targetName) {
      continue;
    }

    const value = cookie.slice(separatorIndex + 1);

    if (!value) {
      return undefined;
    }

    try {
      return decodeURIComponent(value);
    } catch {
      return undefined;
    }
  }

  return undefined;
}
