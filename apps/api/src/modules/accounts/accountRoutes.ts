import { Router } from 'express';
import type { AuthRateLimiters } from '../../security/authRateLimits.js';

import type { EmailSender } from './emailSender.js';
import { createAccountController } from './accountController.js';

export function createAccountRouter(emailSender: EmailSender, rateLimits: AuthRateLimiters) {
  const router = Router();
  const controller = createAccountController(emailSender);

  router.post('/', rateLimits.registrationStart, controller.start);

  router.post('/verify-email', rateLimits.emailVerification, controller.verifyEmail);

  return router;
}
