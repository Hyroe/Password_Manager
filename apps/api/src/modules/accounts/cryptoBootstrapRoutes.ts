import { Router } from 'express';
import { cryptoBootstrapComplete, cryptoBootstrapOptions } from './cryptoBootstrapController.js';
import type { AuthRateLimiters } from '../../security/authRateLimits.js';

export function createCryptoBootstrapRouter(rateLimits: AuthRateLimiters) {
  const router = Router();

  router.post('/options', rateLimits.cryptoBootstrapOptions, cryptoBootstrapOptions);

  router.post('/complete', rateLimits.cryptoBootstrapComplete, cryptoBootstrapComplete);

  return router;
}
