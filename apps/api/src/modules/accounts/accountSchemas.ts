import { z } from 'zod';

export const startRegistrationSchema = z.object({
  email: z.string().trim().email().max(320),
});

export const verifyEmailSchema = z.object({
  registrationId: z.string().uuid(),
  token: z.string().min(1).max(512),
});

export type StartRegistrationInput = z.infer<typeof startRegistrationSchema>;
export type VerifyEmailInput = z.infer<typeof verifyEmailSchema>;
