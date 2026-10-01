import type { RequestHandler } from 'express';

import { createAuthenticatedUserRateLimiter, type RateLimitStoreFactory } from './rateLimit.js';

const FIFTEEN_MINUTES_MS = 15 * 60 * 1000;

const TEN_MINUTES_MS = 10 * 60 * 1000;

export interface SensitiveRateLimiters {
  masterPasswordChange: RequestHandler;
  recoveryComplete: RequestHandler;
  sessionMutation: RequestHandler;
}

export function createSensitiveRateLimiters(
  storeFactory?: RateLimitStoreFactory,
): SensitiveRateLimiters {
  return {
    /*
     * These operations rewrite account-level
     * cryptographic security state.
     */
    masterPasswordChange: createAuthenticatedUserRateLimiter(
      {
        identifier: 'master-password-change',

        windowMs: FIFTEEN_MINUTES_MS,

        limit: 5,
      },

      storeFactory,
    ),

    recoveryComplete: createAuthenticatedUserRateLimiter(
      {
        identifier: 'master-password-recovery',

        windowMs: FIFTEEN_MINUTES_MS,

        limit: 5,
      },

      storeFactory,
    ),

    /*
     * Session management may legitimately
     * involve several devices, so keep this
     * substantially more permissive.
     */
    sessionMutation: createAuthenticatedUserRateLimiter(
      {
        identifier: 'session-management',

        windowMs: TEN_MINUTES_MS,

        limit: 30,
      },

      storeFactory,
    ),
  };
}
