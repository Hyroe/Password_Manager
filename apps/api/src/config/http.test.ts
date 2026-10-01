import { afterEach, describe, expect, it, vi } from 'vitest';

import { createApp } from '../app.js';
import { resolveTrustProxy } from './http.js';

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('HTTP proxy configuration', () => {
  it('does not trust forwarded headers by default', () => {
    vi.stubEnv('TRUST_PROXY_HOPS', '');

    expect(resolveTrustProxy()).toBe(false);

    const app = createApp();

    expect(app.get('trust proxy')).toBe(false);
  });

  it('allows an explicit proxy hop count', () => {
    vi.stubEnv('TRUST_PROXY_HOPS', '1');

    expect(resolveTrustProxy()).toBe(1);

    const app = createApp();

    expect(app.get('trust proxy')).toBe(1);
  });

  it.each(['0', '-1', 'true', 'all', '1.5', 'abc', '11'])(
    'rejects unsafe trust proxy value %s',
    (value) => {
      vi.stubEnv('TRUST_PROXY_HOPS', value);

      expect(() => resolveTrustProxy()).toThrow();
    },
  );
});
