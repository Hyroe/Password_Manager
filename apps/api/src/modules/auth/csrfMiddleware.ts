import type { NextFunction, Request, Response } from 'express';

import { getSessionTokenFromRequest } from './sessionCookie.js';

import { verifyCsrfToken } from './csrfToken.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function isBrowserRequest(req: Request): boolean {
  return Boolean(req.get('origin') || req.get('sec-fetch-site'));
}

export function requireCsrfForBrowserMutation(req: Request, res: Response, next: NextFunction) {
  if (SAFE_METHODS.has(req.method)) {
    next();

    return;
  }

  /*
   * CSRF protects browser requests using
   * cookie-backed authentication.
   *
   * Public requests without a session
   * cookie continue normally.
   */
  const sessionToken = getSessionTokenFromRequest(req);

  if (!sessionToken) {
    next();

    return;
  }

  /*
   * Preserve direct API/integration clients.
   *
   * Origin protection independently ensures
   * actual browser mutations cannot simply
   * omit browser request metadata.
   */
  if (!isBrowserRequest(req)) {
    next();

    return;
  }

  const csrfToken = req.get('x-csrf-token');

  if (!csrfToken || !verifyCsrfToken(sessionToken, csrfToken)) {
    res.status(403).json({
      error: {
        code: 'INVALID_CSRF',

        message: 'CSRF validation failed.',
      },
    });

    return;
  }

  next();
}
