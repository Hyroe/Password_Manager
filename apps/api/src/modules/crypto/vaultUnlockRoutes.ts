import { Router } from 'express';

import { requireSession } from '../auth/sessionMiddleware.js';

import { getVaultUnlock } from './vaultUnlockController.js';

export function createVaultUnlockRouter() {
  const router = Router();

  router.get('/unlock', requireSession, getVaultUnlock);

  return router;
}
