import request from 'supertest';
import { describe, expect, it, vi } from 'vitest';

import { createApp } from '../app.js';

function stubProductionEnvironment(): void {
  vi.stubEnv('NODE_ENV', 'production');
  vi.stubEnv('WEBAUTHN_RP_ID', 'example.com');
  vi.stubEnv('WEBAUTHN_ORIGIN', 'https://vault.example.com');
}

describe('HTTP security headers', () => {
  it('applies the browser security baseline', async () => {
    const response = await request(createApp()).get('/api/v1/health').expect(200);

    expect(response.headers['x-powered-by']).toBeUndefined();

    expect(response.headers['x-content-type-options']).toBe('nosniff');

    expect(response.headers['x-frame-options']).toBe('DENY');

    expect(response.headers['referrer-policy']).toBe('no-referrer');

    expect(response.headers['cross-origin-opener-policy']).toBe('same-origin');

    expect(response.headers['cross-origin-resource-policy']).toBe('same-origin');

    expect(response.headers['permissions-policy']).toBe(
      'camera=(), geolocation=(), microphone=(), payment=(), usb=()',
    );

    const csp = response.headers['content-security-policy'];

    expect(csp).toContain("default-src 'none'");

    expect(csp).toContain("script-src 'self' 'wasm-unsafe-eval'");

    expect(csp).toContain("script-src-attr 'none'");

    expect(csp).toContain("object-src 'none'");

    expect(csp).toContain("frame-ancestors 'none'");

    /*
     * Vitest runs in test mode.
     *
     * Local HTTP must not be upgraded
     * or pinned through HSTS.
     */
    expect(csp).not.toContain('upgrade-insecure-requests');

    expect(response.headers['strict-transport-security']).toBeUndefined();
  });
  it('enables HTTPS-oriented protections in production', async () => {
    stubProductionEnvironment();

    const response = await request(createApp()).get('/api/v1/health').expect(200);

    const csp = response.headers['content-security-policy'];

    expect(csp).toContain('upgrade-insecure-requests');

    expect(response.headers['strict-transport-security']).toContain('max-age=31536000');

    /*
     * We intentionally have not committed
     * to includeSubDomains or preload yet.
     */
    expect(response.headers['strict-transport-security']).not.toContain('includeSubDomains');

    expect(response.headers['strict-transport-security']).not.toContain('preload');
  });
});
