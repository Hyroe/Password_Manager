import { Router } from 'express';

import { getMe, listSessions, logout, revokeSessionRequest } from './sessionController.js';

import { requireSession } from './sessionMiddleware.js';

export function createSessionRouter() {
  const router = Router();

  router.get('/me', requireSession, getMe);

  router.get('/sessions', requireSession, listSessions);

  router.delete('/sessions/:sessionId', requireSession, revokeSessionRequest);

  router.post('/auth/logout', requireSession, logout);

  return router;
}
