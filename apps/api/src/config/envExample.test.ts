import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { parse } from 'dotenv';
import { describe, expect, it } from 'vitest';

import { parseEnvironment } from './env.js';

const envExamplePath = fileURLToPath(new URL('../../../../.env.example', import.meta.url));

describe('example environment configuration', () => {
  it('matches the runtime environment contract', () => {
    const source = parse(readFileSync(envExamplePath, 'utf8'));

    expect(() => parseEnvironment(source)).not.toThrow();
  });

  it('documents a development-safe WebAuthn configuration', () => {
    const source = parse(readFileSync(envExamplePath, 'utf8'));

    const environment = parseEnvironment(source);

    expect(environment.NODE_ENV).toBe('development');

    expect(environment.WEBAUTHN_RP_ID).toBe('localhost');

    expect(environment.WEBAUTHN_ORIGIN).toBe('http://localhost:5173');
  });

  it('does not enable proxy trust implicitly', () => {
    const source = parse(readFileSync(envExamplePath, 'utf8'));

    const environment = parseEnvironment(source);

    expect(environment.TRUST_PROXY_HOPS).toBeUndefined();
  });
});
