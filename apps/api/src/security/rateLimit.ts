import { rateLimit, type Store } from 'express-rate-limit';

export interface RateLimitPolicy {
  identifier: string;

  windowMs: number;
  limit: number;
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

    /*
     * Use the standardized combined
     * RateLimit header.
     */
    standardHeaders: 'draft-8' as const,

    legacyHeaders: false,

    /*
     * Do not silently disable protection
     * when an external store fails.
     */
    passOnStoreError: false,

    /*
     * Explicitly freeze the IPv6 grouping
     * behavior used by the default IP key.
     */
    ipv6Subnet: 56,

    message: RATE_LIMITED_RESPONSE,
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
