import { z } from 'zod';

export const passkeyLoginVerifySchema = z.object({
  challengeId: z.string().uuid(),
  credential: z.unknown(),
});
