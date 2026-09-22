import type { Request, Response } from 'express';

import type { EmailSender } from './emailSender.js';
import { startRegistrationSchema, verifyEmailSchema } from './accountSchemas.js';
import { startRegistration, verifyRegistrationEmail } from './accountService.js';

export function createAccountController(emailSender: EmailSender) {
  return {
    start: async (req: Request, res: Response) => {
      const result = startRegistrationSchema.safeParse(req.body);

      if (!result.success) {
        res.status(400).json({
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid registration request.',
          },
        });

        return;
      }

      const registration = await startRegistration(result.data.email);

      await emailSender.sendVerificationEmail({
        email: result.data.email,
        registrationId: registration.registrationId,
        token: registration.verificationToken,
      });

      res.status(202).json({
        registrationId: registration.registrationId,
      });
    },

    verifyEmail: async (req: Request, res: Response) => {
      const result = verifyEmailSchema.safeParse(req.body);

      if (!result.success) {
        res.status(400).json({
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid email verification request.',
          },
        });

        return;
      }

      try {
        const verification = await verifyRegistrationEmail(
          result.data.registrationId,
          result.data.token,
        );

        res.status(200).json(verification);
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
  };
}
