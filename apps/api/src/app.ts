import express from 'express';

import { createAccountRouter } from './modules/accounts/accountRoutes.js';
import { noopEmailSender, type EmailSender } from './modules/accounts/emailSender.js';
import { createPasskeyRouter } from './modules/auth/passkeyRoutes.js';
import { simpleWebAuthnProvider, type WebAuthnProvider } from './modules/auth/webauthnProvider.js';
import { createCryptoBootstrapRouter } from './modules/accounts/cryptoBootstrapRoutes.js';
import {
  simplePasskeyAuthenticationProvider,
  type PasskeyAuthenticationProvider,
} from './modules/auth/passkeyAuthenticationProvider.js';
import { createSessionRouter } from './modules/auth/sessionRoutes.js';
import { createVaultUnlockRouter } from './modules/crypto/vaultUnlockRoutes.js';

import { createPasskeyLoginRouter } from './modules/auth/passkeyLoginRoutes.js';
import { createVaultItemRouter } from './modules/vault/vaultItemRoutes.js';

import { createHttpSecurityHeaders, permissionsPolicy } from './security/httpSecurity.js';
import { resolveTrustProxy } from './config/http.js';
import { createOriginProtection } from './security/originProtection.js';
import { requireCsrfForBrowserMutation } from './modules/auth/csrfMiddleware.js';

import { createAuthRateLimiters } from './security/authRateLimits.js';

import type { RateLimitStoreFactory } from './security/rateLimit.js';
import { createSensitiveRateLimiters } from './security/sensitiveRateLimits.js';

interface AppDependencies {
  emailSender?: EmailSender;
  webAuthnProvider?: WebAuthnProvider;
  passkeyAuthenticationProvider?: PasskeyAuthenticationProvider;

  rateLimitStoreFactory?: RateLimitStoreFactory;
}

export function createApp(dependencies: AppDependencies = {}) {
  const app = express();

  app.set('trust proxy', resolveTrustProxy());

  app.disable('x-powered-by');

  app.use(createHttpSecurityHeaders());

  app.use(permissionsPolicy);

  app.use(createOriginProtection());

  app.use(requireCsrfForBrowserMutation);

  const emailSender = dependencies.emailSender ?? noopEmailSender;
  const webAuthnProvider = dependencies.webAuthnProvider ?? simpleWebAuthnProvider;
  const passkeyAuthenticationProvider =
    dependencies.passkeyAuthenticationProvider ?? simplePasskeyAuthenticationProvider;

  const authRateLimits = createAuthRateLimiters(dependencies.rateLimitStoreFactory);
  const sensitiveRateLimits = createSensitiveRateLimiters(dependencies.rateLimitStoreFactory);

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

  app.use('/api/v1/accounts', createAccountRouter(emailSender, authRateLimits));

  app.use('/api/v1/auth/passkeys', createPasskeyRouter(webAuthnProvider, authRateLimits));

  app.use('/api/v1/accounts/crypto', createCryptoBootstrapRouter(authRateLimits));

  app.use(
    '/api/v1/auth/passkeys',
    createPasskeyLoginRouter(passkeyAuthenticationProvider, authRateLimits),
  );

  app.use('/api/v1', createSessionRouter(sensitiveRateLimits));

  app.use('/api/v1/crypto', createVaultUnlockRouter(sensitiveRateLimits));

  app.use('/api/v1/vaults', createVaultItemRouter());

  return app;
}

export const app = createApp();
