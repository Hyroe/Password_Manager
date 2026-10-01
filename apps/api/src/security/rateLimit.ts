import { rateLimit, type Store } from 'express-rate-limit';

import type { Request, RequestHandler } from 'express';

export interface RateLimitPolicy {
  identifier: string;

  windowMs: number;
  limit: number;

  keyGenerator?: (req: Request) => string;
}

export type RateLimitStoreFactory = (identifier: string) => Store | undefined;

const RATE_LIMITED_RESPONSE = {
  error: {
    code: 'RATE_LIMITED',
    message: 'Too many requests. Try again later.',
  },
} as const;

export function createRateLimiter(policy: RateLimitPolicy, storeFactory?: RateLimitStoreFactory) {
  const store = storeFactory?.(policy.identifier);

  const baseOptions = {
    windowMs: policy.windowMs,
    limit: policy.limit,

    identifier: policy.identifier,

    standardHeaders: 'draft-8' as const,

    legacyHeaders: false,

    passOnStoreError: false,

    message: RATE_LIMITED_RESPONSE,

    ...(policy.keyGenerator
      ? {
          keyGenerator: policy.keyGenerator,
        }
      : {
          /*
           * Only applies when the default
           * IP-based key generator is used.
           */
          ipv6Subnet: 56,
        }),
  };

  if (store) {
    return rateLimit({
      ...baseOptions,
      store,
    });
  }

  /*
   * Local/test environments can use the
   * library's process-local MemoryStore.
   *
   * A shared store can be injected later
   * without changing route policies.
   */
  return rateLimit(baseOptions);
}

export function createAuthenticatedUserRateLimiter(
  policy: Omit<RateLimitPolicy, 'keyGenerator'>,
  storeFactory?: RateLimitStoreFactory,
): RequestHandler {
  return createRateLimiter(
    {
      ...policy,

      keyGenerator(req) {
        /*
         * Authenticated rate limiters must
         * be mounted after requireSession.
         *
         * If a route is ever misconfigured,
         * use one shared fail-closed bucket
         * instead of bypassing protection.
         */
        if (!req.auth) {
          return 'missing-auth';
        }

        return `user:${req.auth.userId}`;
      },
    },

    storeFactory,
  );
}
