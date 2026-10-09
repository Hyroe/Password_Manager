import type { NextFunction, Request, Response } from 'express';

import { sessionCookieClearOptions, sessionCookieName } from '../../config/session.js';

import { getBearerSessionTokenFromRequest } from './sessionBearer.js';

import { getSessionTokenFromRequest } from './sessionCookie.js';

import { resolveSession } from './sessionService.js';

function authenticationRequired(res: Response): void {
  res.status(401).json({
    error: {
      code: 'AUTHENTICATION_REQUIRED',

      message: 'Authentication is required.',
    },
  });
}

export async function requireSession(req: Request, res: Response, next: NextFunction) {
  try {
    const cookieToken = getSessionTokenFromRequest(req);

    const bearer = getBearerSessionTokenFromRequest(req);

    /*
     * Authentication transports are mutually
     * exclusive.
     *
     * Never choose one credential silently
     * when multiple mechanisms are present.
     */
    if (cookieToken && bearer.kind !== 'ABSENT') {
      authenticationRequired(res);

      return;
    }

    if (!cookieToken && bearer.kind === 'INVALID') {
      authenticationRequired(res);

      return;
    }

    if (!cookieToken && bearer.kind === 'ABSENT') {
      authenticationRequired(res);

      return;
    }

    const transport: 'COOKIE' | 'BEARER' = cookieToken ? 'COOKIE' : 'BEARER';

    const sessionToken = cookieToken ?? (bearer.kind === 'TOKEN' ? bearer.token : undefined);

    if (!sessionToken) {
      authenticationRequired(res);

      return;
    }

    const expectedClientKind = transport === 'COOKIE' ? 'WEB' : 'BROWSER_EXTENSION';

    const session = await resolveSession(sessionToken, expectedClientKind);

    if (!session) {
      /*
       * Only an invalid cookie-backed session
       * may clear the web session cookie.
       *
       * Bearer failures must never mutate the
       * independent web authentication state.
       */
      if (transport === 'COOKIE') {
        res.clearCookie(sessionCookieName(), sessionCookieClearOptions());
      }

      authenticationRequired(res);

      return;
    }

    req.auth = {
      ...session,

      transport,
    };

    next();
  } catch (error) {
    next(error);
  }
}
