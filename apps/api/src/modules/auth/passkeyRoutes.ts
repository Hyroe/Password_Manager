import { Router } from 'express';
import type { AuthRateLimiters } from '../../security/authRateLimits.js';

import { createPasskeyController } from './passkeyController.js';
import type { WebAuthnProvider } from './webauthnProvider.js';

export function createPasskeyRouter(provider: WebAuthnProvider, rateLimits: AuthRateLimiters) {
  const router = Router();
  const controller = createPasskeyController(provider);

  router.post(
    '/register/options',
    rateLimits.passkeyRegistrationOptions,
    controller.registrationOptions,
  );

  router.post(
    '/register/verify',
    rateLimits.passkeyRegistrationVerify,
    controller.registrationVerify,
  );

  return router;
}
