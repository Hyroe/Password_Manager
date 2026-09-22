import type { Request, Response } from 'express';
import type { RegistrationResponseJSON } from '@simplewebauthn/server';

import { registrationOptionsSchema, registrationVerifySchema } from './passkeySchemas.js';
import { createPasskeyRegistrationOptions, verifyPasskeyRegistration } from './passkeyService.js';
import type { WebAuthnProvider } from './webauthnProvider.js';

export function createPasskeyController(provider: WebAuthnProvider) {
  return {
    registrationOptions: async (req: Request, res: Response) => {
      const result = registrationOptionsSchema.safeParse(req.body);

      if (!result.success) {
        res.status(400).json({
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid passkey registration request.',
          },
        });

        return;
      }

      try {
        const response = await createPasskeyRegistrationOptions(
          result.data.registrationId,
          result.data.registrationToken,
          provider,
        );

        res.status(200).json(response);
      } catch (error) {
        if (error instanceof Error && error.message === 'INVALID_REGISTRATION') {
          res.status(400).json({
            error: {
              code: 'REGISTRATION_INVALID',
              message: 'The registration request is invalid or expired.',
            },
          });

          return;
        }

        throw error;
      }
    },

    registrationVerify: async (req: Request, res: Response) => {
      const result = registrationVerifySchema.safeParse(req.body);

      if (!result.success) {
        res.status(400).json({
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid passkey verification request.',
          },
        });

        return;
      }

      try {
        const response = await verifyPasskeyRegistration(
          result.data.registrationId,
          result.data.registrationToken,
          result.data.challengeId,
          result.data.credential as RegistrationResponseJSON,
          provider,
        );

        res.status(200).json(response);
      } catch (error) {
        if (
          error instanceof Error &&
          (error.message === 'INVALID_REGISTRATION' ||
            error.message === 'INVALID_CHALLENGE' ||
            error.message === 'WEBAUTHN_VERIFICATION_FAILED')
        ) {
          res.status(400).json({
            error: {
              code: 'PASSKEY_REGISTRATION_FAILED',
              message: 'Passkey registration could not be completed.',
            },
          });

          return;
        }

        throw error;
      }
    },
  };
}
