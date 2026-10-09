import type { Request, Response } from 'express';

import { sessionCookieClearOptions, sessionCookieName } from '../../config/session.js';

import {
  listActiveSessions,
  revokeOtherSessions,
  revokeSession,
  revokeUserSession,
} from './sessionService.js';

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

  if (req.auth?.transport === 'COOKIE') {
    res.clearCookie(sessionCookieName(), sessionCookieClearOptions());
  }

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

      clientKind: session.clientKind,

      deviceLabel: session.deviceLabel,

      createdAt: session.createdAt.toISOString(),

      lastSeenAt: session.lastSeenAt.toISOString(),

      idleExpiresAt: session.idleExpiresAt.toISOString(),

      absoluteExpiresAt: session.absoluteExpiresAt.toISOString(),

      current: session.current,
    })),
  });
}

export async function revokeSessionRequest(req: Request, res: Response) {
  if (!req.auth) {
    res.status(401).json({
      error: {
        code: 'AUTHENTICATION_REQUIRED',

        message: 'Authentication is required.',
      },
    });

    return;
  }

  const sessionId = req.params.sessionId;

  const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

  if (typeof sessionId !== 'string' || !uuidPattern.test(sessionId)) {
    res.status(400).json({
      error: {
        code: 'VALIDATION_ERROR',

        message: 'Invalid session identifier.',
      },
    });

    return;
  }

  /*
   * Intentionally return the same successful
   * response whether the session:
   *
   * - existed,
   * - was already revoked,
   * - or belongs to another account.
   *
   * This keeps DELETE idempotent and avoids
   * exposing session existence across users.
   */
  await revokeUserSession(req.auth.userId, sessionId);

  if (sessionId === req.auth.sessionId && req.auth.transport === 'COOKIE') {
    res.clearCookie(sessionCookieName(), sessionCookieClearOptions());
  }

  res.status(204).end();
}

export async function revokeOtherSessionsRequest(req: Request, res: Response) {
  if (!req.auth) {
    res.status(401).json({
      error: {
        code: 'AUTHENTICATION_REQUIRED',

        message: 'Authentication is required.',
      },
    });

    return;
  }

  await revokeOtherSessions(req.auth.userId, req.auth.sessionId);

  /*
   * The current session intentionally survives.
   *
   * Therefore:
   * - do not revoke it
   * - do not clear the current browser cookie
   */
  res.status(204).end();
}
