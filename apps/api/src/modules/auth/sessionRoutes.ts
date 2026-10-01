import { Router } from 'express';

import {
  getMe,
  listSessions,
  logout,
  revokeOtherSessionsRequest,
  revokeSessionRequest,
} from './sessionController.js';

import type { SensitiveRateLimiters } from '../../security/sensitiveRateLimits.js';

import { requireSession } from './sessionMiddleware.js';
import { getCsrfToken } from './csrfController.js';

export function createSessionRouter(rateLimits: SensitiveRateLimiters) {
  const router = Router();

  router.get('/me', requireSession, getMe);

  router.get('/auth/csrf', requireSession, getCsrfToken);

  router.get('/sessions', requireSession, listSessions);

  router.post(
    '/sessions/revoke-others',
    requireSession,
    rateLimits.sessionMutation,
    revokeOtherSessionsRequest,
  );

  router.delete(
    '/sessions/:sessionId',
    requireSession,
    rateLimits.sessionMutation,
    revokeSessionRequest,
  );

  router.post('/auth/logout', requireSession, logout);

  return router;
}
