import { z } from 'zod';

export const registrationOptionsSchema = z.object({
  registrationId: z.string().uuid(),
  registrationToken: z.string().min(1).max(512),
});

export const registrationVerifySchema = z.object({
  registrationId: z.string().uuid(),
  registrationToken: z.string().min(1).max(512),
  challengeId: z.string().uuid(),
  credential: z.unknown(),
});
