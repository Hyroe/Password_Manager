import type { Request, Response } from 'express';

import { sessionCookieClearOptions, sessionCookieName } from '../../config/session.js';

import { revokeSession } from './sessionService.js';

export async function getMe(req: Request, res: Response) {
  if (!req.auth) {
    res.status(401).json({
      error: {
        code: 'AUTHENTICATION_REQUIRED',

        message: 'Authentication is required.',
      },
    });

    return;
  }

  res.status(200).json({
    user: {
      id: req.auth.userId,
      email: req.auth.email,
    },

    state: 'AUTHENTICATED_LOCKED',

    session: {
      absoluteExpiresAt: req.auth.absoluteExpiresAt,
    },
  });
}

export async function logout(req: Request, res: Response) {
  if (req.auth) {
    await revokeSession(req.auth.sessionId);
  }

  res.clearCookie(sessionCookieName(), sessionCookieClearOptions());

  res.status(204).end();
}
