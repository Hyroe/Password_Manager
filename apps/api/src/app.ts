import express from 'express';

import { createAccountRouter } from './modules/accounts/accountRoutes.js';
import { noopEmailSender, type EmailSender } from './modules/accounts/emailSender.js';

interface AppDependencies {
  emailSender?: EmailSender;
}

export function createApp(dependencies: AppDependencies = {}) {
  const app = express();

  const emailSender = dependencies.emailSender ?? noopEmailSender;

  app.disable('x-powered-by');

  app.use(
    express.json({
      limit: '2mb',
    }),
  );

  app.get('/api/v1/health', (_req, res) => {
    res.status(200).json({
      status: 'ok',
    });
  });

  app.use('/api/v1/accounts', createAccountRouter(emailSender));

  return app;
}

export const app = createApp();
