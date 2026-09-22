import { Router } from 'express';

import type { EmailSender } from './emailSender.js';
import { createAccountController } from './accountController.js';

export function createAccountRouter(emailSender: EmailSender) {
  const router = Router();
  const controller = createAccountController(emailSender);

  router.post('/', controller.start);
  router.post('/verify-email', controller.verifyEmail);

  return router;
}
