import type { AuthenticationResponseJSON } from '@simplewebauthn/server';

import type { Request, Response } from 'express';

import { sessionCookieName, sessionCookieOptions } from '../../config/session.js';

import type { PasskeyAuthenticationProvider } from './passkeyAuthenticationProvider.js';

import { createPasskeyLoginOptions, verifyPasskeyLogin } from './passkeyLoginService.js';

import { passkeyLoginVerifySchema } from './passkeyLoginSchemas.js';

export function createPasskeyLoginController(provider: PasskeyAuthenticationProvider) {
  return {
    options: async (_req: Request, res: Response) => {
      const result = await createPasskeyLoginOptions(provider);

      res.status(200).json(result);
    },

    verify: async (req: Request, res: Response) => {
      const parsed = passkeyLoginVerifySchema.safeParse(req.body);

      if (!parsed.success) {
        res.status(400).json({
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid authentication request.',
          },
        });

        return;
      }

      try {
        const result = await verifyPasskeyLogin(
          parsed.data.challengeId,

          parsed.data.credential as AuthenticationResponseJSON,

          provider,
        );

        res.cookie(sessionCookieName(), result.sessionToken, sessionCookieOptions());

        res.status(200).json({
          user: result.user,

          state: 'AUTHENTICATED_LOCKED',

          expiresAt: result.absoluteExpiresAt,
        });
      } catch {
        res.status(401).json({
          error: {
            code: 'AUTHENTICATION_FAILED',

            message: 'Passkey authentication failed.',
          },
        });
      }
    },
  };
}
