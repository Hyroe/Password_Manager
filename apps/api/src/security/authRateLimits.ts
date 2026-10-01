import type { RequestHandler } from 'express';

import { createRateLimiter, type RateLimitStoreFactory } from './rateLimit.js';

const TEN_MINUTES_MS = 10 * 60 * 1000;

export interface AuthRateLimiters {
  registrationStart: RequestHandler;
  emailVerification: RequestHandler;

  passkeyRegistrationOptions: RequestHandler;
  passkeyRegistrationVerify: RequestHandler;

  loginOptions: RequestHandler;
  loginVerify: RequestHandler;

  cryptoBootstrapOptions: RequestHandler;
  cryptoBootstrapComplete: RequestHandler;
}

export function createAuthRateLimiters(storeFactory?: RateLimitStoreFactory): AuthRateLimiters {
  return {
    registrationStart: createRateLimiter(
      {
        identifier: 'registration-start',

        windowMs: TEN_MINUTES_MS,

        limit: 10,
      },

      storeFactory,
    ),

    emailVerification: createRateLimiter(
      {
        identifier: 'email-verification',

        windowMs: TEN_MINUTES_MS,

        limit: 20,
      },

      storeFactory,
    ),

    passkeyRegistrationOptions: createRateLimiter(
      {
        identifier: 'passkey-registration-options',

        windowMs: TEN_MINUTES_MS,

        limit: 20,
      },

      storeFactory,
    ),

    passkeyRegistrationVerify: createRateLimiter(
      {
        identifier: 'passkey-registration-verify',

        windowMs: TEN_MINUTES_MS,

        limit: 20,
      },

      storeFactory,
    ),

    /*
     * Login limits are intentionally more
     * permissive than registration limits.
     *
     * Multiple users may legitimately share
     * one public/NAT IP.
     */
    loginOptions: createRateLimiter(
      {
        identifier: 'passkey-login-options',

        windowMs: TEN_MINUTES_MS,

        limit: 60,
      },

      storeFactory,
    ),

    loginVerify: createRateLimiter(
      {
        identifier: 'passkey-login-verify',

        windowMs: TEN_MINUTES_MS,

        limit: 60,
      },

      storeFactory,
    ),

    cryptoBootstrapOptions: createRateLimiter(
      {
        identifier: 'crypto-bootstrap-options',

        windowMs: TEN_MINUTES_MS,

        limit: 20,
      },

      storeFactory,
    ),

    cryptoBootstrapComplete: createRateLimiter(
      {
        identifier: 'crypto-bootstrap-complete',

        windowMs: TEN_MINUTES_MS,

        limit: 20,
      },

      storeFactory,
    ),
  };
}
