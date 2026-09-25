import { Router } from 'express';

import { getMe, logout } from './sessionController.js';

import { requireSession } from './sessionMiddleware.js';

export function createSessionRouter() {
  const router = Router();

  router.get('/me', requireSession, getMe);

  router.post('/auth/logout', requireSession, logout);

  return router;
}
