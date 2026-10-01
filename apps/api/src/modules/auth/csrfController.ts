import type { Request, Response } from 'express';

import { getSessionTokenFromRequest } from './sessionCookie.js';

import { deriveCsrfToken } from './csrfToken.js';

export function getCsrfToken(req: Request, res: Response) {
  const sessionToken = getSessionTokenFromRequest(req);

  /*
   * This route must remain behind
   * requireSession.
   *
   * Keep the explicit check so moving the
   * controller accidentally cannot turn it
   * into an unauthenticated token endpoint.
   */
  if (!req.auth || !sessionToken) {
    res.status(401).json({
      error: {
        code: 'AUTHENTICATION_REQUIRED',

        message: 'Authentication is required.',
      },
    });

    return;
  }

  /*
   * CSRF tokens are session-bound and must
   * not be cached by intermediaries.
   */
  res.setHeader('Cache-Control', 'no-store');

  res.status(200).json({
    csrfToken: deriveCsrfToken(sessionToken),
  });
}
