import { Router } from 'express';

import { requireSession } from '../auth/sessionMiddleware.js';

import type { SensitiveRateLimiters } from '../../security/sensitiveRateLimits.js';

import {
  changeMasterPasswordRequest,
  completeMasterPasswordRecoveryRequest,
  getMasterPasswordRecovery,
  getVaultUnlock,
} from './vaultUnlockController.js';

export function createVaultUnlockRouter(rateLimits: SensitiveRateLimiters) {
  const router = Router();

  router.get('/unlock', requireSession, getVaultUnlock);

  router.get('/recovery', requireSession, getMasterPasswordRecovery);

  router.post(
    '/recovery/complete',
    requireSession,
    rateLimits.recoveryComplete,
    completeMasterPasswordRecoveryRequest,
  );

  router.post(
    '/master-password/change',
    requireSession,
    rateLimits.masterPasswordChange,
    changeMasterPasswordRequest,
  );

  return router;
}
