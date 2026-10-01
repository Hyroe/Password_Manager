import { describe, expect, it } from 'vitest';

import { createAuthRateLimiters } from './authRateLimits.js';

describe('authentication rate-limit policies', () => {
  it('creates independent limiters for every public authentication surface', () => {
    const limits = createAuthRateLimiters();

    expect(limits.registrationStart).toBeTypeOf('function');

    expect(limits.emailVerification).toBeTypeOf('function');

    expect(limits.passkeyRegistrationOptions).toBeTypeOf('function');

    expect(limits.passkeyRegistrationVerify).toBeTypeOf('function');

    expect(limits.loginOptions).toBeTypeOf('function');

    expect(limits.loginVerify).toBeTypeOf('function');

    expect(limits.cryptoBootstrapOptions).toBeTypeOf('function');

    expect(limits.cryptoBootstrapComplete).toBeTypeOf('function');
  });

  it('does not reuse one limiter instance across distinct endpoints', () => {
    const limits = createAuthRateLimiters();

    const handlers = Object.values(limits);

    expect(new Set(handlers).size).toBe(handlers.length);
  });
});
