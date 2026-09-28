import { Router } from 'express';

import { requireSession } from '../auth/sessionMiddleware.js';

import {
  completeMasterPasswordRecoveryRequest,
  getMasterPasswordRecovery,
  getVaultUnlock,
} from './vaultUnlockController.js';

export function createVaultUnlockRouter() {
  const router = Router();

  router.get('/unlock', requireSession, getVaultUnlock);

  router.get('/recovery', requireSession, getMasterPasswordRecovery);

  router.post('/recovery/complete', requireSession, completeMasterPasswordRecoveryRequest);

  return router;
}
