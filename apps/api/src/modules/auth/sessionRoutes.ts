import { Router } from 'express';

import {
  getMe,
  listSessions,
  logout,
  revokeOtherSessionsRequest,
  revokeSessionRequest,
} from './sessionController.js';

import { requireSession } from './sessionMiddleware.js';
import { getCsrfToken } from './csrfController.js';

export function createSessionRouter() {
  const router = Router();

  router.get('/me', requireSession, getMe);

  router.get('/auth/csrf', requireSession, getCsrfToken);

  router.get('/sessions', requireSession, listSessions);

  router.post('/sessions/revoke-others', requireSession, revokeOtherSessionsRequest);

  router.delete('/sessions/:sessionId', requireSession, revokeSessionRequest);

  router.post('/auth/logout', requireSession, logout);

  return router;
}
