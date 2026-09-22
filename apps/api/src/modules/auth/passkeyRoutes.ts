import { Router } from 'express';

import { createPasskeyController } from './passkeyController.js';
import type { WebAuthnProvider } from './webauthnProvider.js';

export function createPasskeyRouter(provider: WebAuthnProvider) {
  const router = Router();
  const controller = createPasskeyController(provider);

  router.post('/register/options', controller.registrationOptions);
  router.post('/register/verify', controller.registrationVerify);

  return router;
}
