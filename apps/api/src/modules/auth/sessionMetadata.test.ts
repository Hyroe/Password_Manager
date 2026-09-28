import { describe, expect, it } from 'vitest';

import {
  describeSessionDevice,
  normalizeSessionUserAgent,
  SESSION_USER_AGENT_MAX_LENGTH,
} from './sessionMetadata.js';

describe('session device metadata', () => {
  it('normalizes an empty User-Agent to null', () => {
    expect(normalizeSessionUserAgent(undefined)).toBeNull();

    expect(normalizeSessionUserAgent('   ')).toBeNull();
  });

  it('limits persisted User-Agent length', () => {
    const value = 'x'.repeat(SESSION_USER_AGENT_MAX_LENGTH + 100);

    const normalized = normalizeSessionUserAgent(value);

    expect(normalized).not.toBeNull();

    expect(normalized?.length).toBe(SESSION_USER_AGENT_MAX_LENGTH);
  });

  it('describes Chrome on Windows', () => {
    const userAgent =
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/153.0.0.0 Safari/537.36';

    expect(describeSessionDevice(userAgent)).toBe('Chrome on Windows');
  });

  it('describes Safari on macOS', () => {
    const userAgent =
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15';

    expect(describeSessionDevice(userAgent)).toBe('Safari on macOS');
  });

  it('describes Firefox on Linux', () => {
    const userAgent = 'Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0';

    expect(describeSessionDevice(userAgent)).toBe('Firefox on Linux');
  });

  it('returns Unknown device for unavailable metadata', () => {
    expect(describeSessionDevice(null)).toBe('Unknown device');

    expect(describeSessionDevice('custom-client')).toBe('Unknown device');
  });
});
