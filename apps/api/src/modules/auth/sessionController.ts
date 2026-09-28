import type { Request, Response } from 'express';

import { sessionCookieClearOptions, sessionCookieName } from '../../config/session.js';

import { listActiveSessions, revokeSession } from './sessionService.js';

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

export async function listSessions(req: Request, res: Response) {
  if (!req.auth) {
    res.status(401).json({
      error: {
        code: 'AUTHENTICATION_REQUIRED',

        message: 'Authentication is required.',
      },
    });

    return;
  }

  const sessions = await listActiveSessions(req.auth.userId, req.auth.sessionId);

  res.status(200).json({
    sessions: sessions.map((session) => ({
      id: session.id,

      createdAt: session.createdAt.toISOString(),

      lastSeenAt: session.lastSeenAt.toISOString(),

      idleExpiresAt: session.idleExpiresAt.toISOString(),

      absoluteExpiresAt: session.absoluteExpiresAt.toISOString(),

      current: session.current,
    })),
  });
}
