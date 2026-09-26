import { Router } from 'express';

import { requireSession } from '../auth/sessionMiddleware.js';

import { createVaultItemController, reserveVaultItemController } from './vaultItemController.js';

export function createVaultItemRouter() {
  const router = Router();

  router.post('/:vaultId/items/options', requireSession, reserveVaultItemController);

  router.post('/:vaultId/items', requireSession, createVaultItemController);

  return router;
}
