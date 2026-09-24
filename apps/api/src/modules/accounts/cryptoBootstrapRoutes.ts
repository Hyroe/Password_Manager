import { Router } from 'express';
import { cryptoBootstrapComplete, cryptoBootstrapOptions } from './cryptoBootstrapController.js';

export function createCryptoBootstrapRouter() {
  const router = Router();

  router.post('/options', cryptoBootstrapOptions);
  router.post('/complete', cryptoBootstrapComplete);

  return router;
}
