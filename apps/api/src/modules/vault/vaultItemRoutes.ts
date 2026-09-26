import { Router } from 'express';

import { requireSession } from '../auth/sessionMiddleware.js';

import {
  createVaultItemController,
  createVaultItemRevisionController,
  deleteVaultItemController,
  getVaultItemController,
  getVaultItemUpdateOptionsController,
  listVaultItemsController,
  reserveVaultItemController,
  restoreVaultItemController,
} from './vaultItemController.js';

export function createVaultItemRouter() {
  const router = Router();

  router.post('/:vaultId/items/options', requireSession, reserveVaultItemController);

  router.post('/:vaultId/items', requireSession, createVaultItemController);

  router.get('/:vaultId/items', requireSession, listVaultItemsController);

  router.get('/:vaultId/items/:itemId', requireSession, getVaultItemController);

  router.post(
    '/:vaultId/items/:itemId/revisions/options',
    requireSession,
    getVaultItemUpdateOptionsController,
  );

  router.post(
    '/:vaultId/items/:itemId/revisions',
    requireSession,
    createVaultItemRevisionController,
  );

  router.post('/:vaultId/items/:itemId/restore', requireSession, restoreVaultItemController);

  router.delete('/:vaultId/items/:itemId', requireSession, deleteVaultItemController);

  return router;
}
