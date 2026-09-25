import type { NextFunction, Request, Response } from 'express';

import { sessionCookieClearOptions, sessionCookieName } from '../../config/session.js';

import { getSessionTokenFromRequest } from './sessionCookie.js';

import { resolveSession } from './sessionService.js';

export async function requireSession(req: Request, res: Response, next: NextFunction) {
  try {
    const sessionToken = getSessionTokenFromRequest(req);

    if (!sessionToken) {
      res.status(401).json({
        error: {
          code: 'AUTHENTICATION_REQUIRED',

          message: 'Authentication is required.',
        },
      });

      return;
    }

    const session = await resolveSession(sessionToken);

    if (!session) {
      res.clearCookie(sessionCookieName(), sessionCookieClearOptions());

      res.status(401).json({
        error: {
          code: 'AUTHENTICATION_REQUIRED',

          message: 'Authentication is required.',
        },
      });

      return;
    }

    req.auth = session;

    next();
  } catch (error) {
    next(error);
  }
}
