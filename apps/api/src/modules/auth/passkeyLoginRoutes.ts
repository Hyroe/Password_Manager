import { Router } from 'express';
import type { AuthRateLimiters } from '../../security/authRateLimits.js';

import type { PasskeyAuthenticationProvider } from './passkeyAuthenticationProvider.js';

import { createPasskeyLoginController } from './passkeyLoginController.js';

export function createPasskeyLoginRouter(
  provider: PasskeyAuthenticationProvider,
  rateLimits: AuthRateLimiters,
) {
  const router = Router();

  const controller = createPasskeyLoginController(provider);

  router.post('/login/options', rateLimits.loginOptions, controller.options);

  router.post('/login/verify', rateLimits.loginVerify, controller.verify);

  return router;
}
