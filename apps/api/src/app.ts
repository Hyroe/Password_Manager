import express from 'express';

import { createAccountRouter } from './modules/accounts/accountRoutes.js';
import { noopEmailSender, type EmailSender } from './modules/accounts/emailSender.js';
import { createPasskeyRouter } from './modules/auth/passkeyRoutes.js';
import { simpleWebAuthnProvider, type WebAuthnProvider } from './modules/auth/webauthnProvider.js';

interface AppDependencies {
  emailSender?: EmailSender;
  webAuthnProvider?: WebAuthnProvider;
}

export function createApp(dependencies: AppDependencies = {}) {
  const app = express();

  const emailSender = dependencies.emailSender ?? noopEmailSender;
  const webAuthnProvider = dependencies.webAuthnProvider ?? simpleWebAuthnProvider;

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

  app.use('/api/v1/auth/passkeys', createPasskeyRouter(webAuthnProvider));

  return app;
}

export const app = createApp();
