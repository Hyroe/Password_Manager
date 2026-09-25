import { Router } from 'express';

import type { PasskeyAuthenticationProvider } from './passkeyAuthenticationProvider.js';

import { createPasskeyLoginController } from './passkeyLoginController.js';

export function createPasskeyLoginRouter(provider: PasskeyAuthenticationProvider) {
  const router = Router();

  const controller = createPasskeyLoginController(provider);

  router.post('/login/options', controller.options);

  router.post('/login/verify', controller.verify);

  return router;
}
