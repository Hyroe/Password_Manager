import { Router } from 'express';

import { requireSession } from '../auth/sessionMiddleware.js';

import {
  createVaultItemController,
  getVaultItemController,
  listVaultItemsController,
  reserveVaultItemController,
} from './vaultItemController.js';

export function createVaultItemRouter() {
  const router = Router();

  router.post('/:vaultId/items/options', requireSession, reserveVaultItemController);

  router.post('/:vaultId/items', requireSession, createVaultItemController);

  router.get('/:vaultId/items', requireSession, listVaultItemsController);

  router.get('/:vaultId/items/:itemId', requireSession, getVaultItemController);

  return router;
}
