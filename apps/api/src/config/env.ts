import 'dotenv/config';

import { z } from 'zod';

function requiredString(message: string) {
  return z.preprocess(
    (value) => {
      if (value === undefined || value === null) {
        return '';
      }

      return value;
    },

    z.string().trim().min(1, {
      message,
    }),
  );
}

const trustProxyHopsSchema = z.preprocess(
  (value) => {
    if (value === undefined || (typeof value === 'string' && value.trim() === '')) {
      return undefined;
    }

    return value;
  },

  z
    .string()
    .trim()
    .regex(/^[1-9]\d*$/, {
      message: 'TRUST_PROXY_HOPS must be a positive integer.',
    })
    .transform(Number)
    .refine((value) => Number.isSafeInteger(value) && value <= 10, {
      message: 'TRUST_PROXY_HOPS is outside the supported range.',
    })
    .optional(),
);

const environmentSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),

  PORT: z.coerce.number().int().min(1).max(65_535).default(3000),

  DATABASE_URL: requiredString('DATABASE_URL is required.'),

  WEBAUTHN_RP_NAME: requiredString('WEBAUTHN_RP_NAME is required.'),

  WEBAUTHN_RP_ID: requiredString('WEBAUTHN_RP_ID is required.'),
  WEBAUTHN_ORIGIN: requiredString('WEBAUTHN_ORIGIN is required.').pipe(
    z.string().url({
      message: 'WEBAUTHN_ORIGIN must be a valid URL.',
    }),
  ),

  TRUST_PROXY_HOPS: trustProxyHopsSchema,
});

export type Environment = z.infer<typeof environmentSchema>;

export function parseEnvironment(source: NodeJS.ProcessEnv): Environment {
  const result = environmentSchema.safeParse(source);

  if (!result.success) {
    /*
     * Do not serialize environment values
     * into startup errors. Configuration may
     * contain credentials or infrastructure
     * secrets.
     */
    const messages = [...new Set(result.error.issues.map((issue) => issue.message))];

    throw new Error(`Invalid environment configuration: ${messages.join(' ')}`);
  }

  return result.data;
}

export function getEnvironment(): Environment {
  return parseEnvironment(process.env);
}
