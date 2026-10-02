import { getEnvironment } from './env.js';

export function resolveTrustProxy(): false | number {
  return getEnvironment().TRUST_PROXY_HOPS ?? false;
}
