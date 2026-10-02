import { describe, expect, it } from 'vitest';

import { parseEnvironment } from './env.js';

function validEnvironment(): NodeJS.ProcessEnv {
  return {
    NODE_ENV: 'test',

    PORT: '3000',

    DATABASE_URL: 'postgresql://user:password@localhost:5432/database',

    WEBAUTHN_RP_NAME: 'Password Manager',

    WEBAUTHN_RP_ID: 'localhost',

    WEBAUTHN_ORIGIN: 'http://localhost:5173',
  };
}

function validProductionEnvironment(): NodeJS.ProcessEnv {
  return {
    ...validEnvironment(),

    NODE_ENV: 'production',

    WEBAUTHN_RP_ID: 'example.com',

    WEBAUTHN_ORIGIN: 'https://vault.example.com',
  };
}

describe('environment configuration', () => {
  it('parses valid runtime configuration', () => {
    const environment = parseEnvironment(validEnvironment());

    expect(environment.NODE_ENV).toBe('test');

    expect(environment.PORT).toBe(3000);

    expect(environment.TRUST_PROXY_HOPS).toBeUndefined();
  });

  it('applies safe development defaults', () => {
    const source = validEnvironment();

    delete source.NODE_ENV;
    delete source.PORT;

    const environment = parseEnvironment(source);

    expect(environment.NODE_ENV).toBe('development');

    expect(environment.PORT).toBe(3000);
  });

  it('rejects a missing database connection string without exposing environment values', () => {
    const source = validEnvironment();

    delete source.DATABASE_URL;

    expect(() => parseEnvironment(source)).toThrow('DATABASE_URL is required.');
  });

  it('rejects incomplete WebAuthn configuration', () => {
    const source = validEnvironment();

    delete source.WEBAUTHN_RP_ID;

    expect(() => parseEnvironment(source)).toThrow('WEBAUTHN_RP_ID is required.');
  });

  it('rejects an invalid WebAuthn origin URL', () => {
    expect(() =>
      parseEnvironment({
        ...validEnvironment(),

        WEBAUTHN_ORIGIN: 'not-a-url',
      }),
    ).toThrow('WEBAUTHN_ORIGIN must be a valid URL.');
  });

  it('parses an explicit trust proxy hop count', () => {
    const environment = parseEnvironment({
      ...validEnvironment(),

      TRUST_PROXY_HOPS: '2',
    });

    expect(environment.TRUST_PROXY_HOPS).toBe(2);
  });

  it.each(['0', '-1', 'abc', '1.5', '11'])('rejects invalid TRUST_PROXY_HOPS=%s', (value) => {
    expect(() =>
      parseEnvironment({
        ...validEnvironment(),

        TRUST_PROXY_HOPS: value,
      }),
    ).toThrow('Invalid environment configuration:');
  });

  it.each(['0', '-1', '65536', 'not-a-port'])('rejects invalid PORT=%s', (value) => {
    expect(() =>
      parseEnvironment({
        ...validEnvironment(),

        PORT: value,
      }),
    ).toThrow('Invalid environment configuration:');
  });

  it('does not include secret values in validation errors', () => {
    const secretValue = 'super-secret-database-password';

    let thrown: unknown;

    try {
      parseEnvironment({
        ...validEnvironment(),

        DATABASE_URL: '',

        SOME_SECRET: secretValue,
      });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(Error);

    expect((thrown as Error).message).not.toContain(secretValue);
  });
  it('accepts a production origin that exactly matches the RP ID', () => {
    const environment = parseEnvironment({
      ...validProductionEnvironment(),

      WEBAUTHN_RP_ID: 'vault.example.com',

      WEBAUTHN_ORIGIN: 'https://vault.example.com',
    });

    expect(environment.NODE_ENV).toBe('production');

    expect(environment.WEBAUTHN_RP_ID).toBe('vault.example.com');

    expect(environment.WEBAUTHN_ORIGIN).toBe('https://vault.example.com');
  });

  it('accepts a production origin below the configured parent RP ID', () => {
    const environment = parseEnvironment(validProductionEnvironment());

    expect(environment.WEBAUTHN_RP_ID).toBe('example.com');

    expect(environment.WEBAUTHN_ORIGIN).toBe('https://vault.example.com');
  });

  it('rejects an insecure production WebAuthn origin', () => {
    expect(() =>
      parseEnvironment({
        ...validProductionEnvironment(),

        WEBAUTHN_ORIGIN: 'http://vault.example.com',
      }),
    ).toThrow('WEBAUTHN_ORIGIN must use HTTPS in production.');
  });

  it('rejects localhost as the production RP ID', () => {
    expect(() =>
      parseEnvironment({
        ...validProductionEnvironment(),

        WEBAUTHN_RP_ID: 'localhost',

        WEBAUTHN_ORIGIN: 'https://localhost',
      }),
    ).toThrow('WEBAUTHN_RP_ID cannot be localhost in production.');
  });

  it('rejects a production origin outside the RP ID domain', () => {
    expect(() =>
      parseEnvironment({
        ...validProductionEnvironment(),

        WEBAUTHN_RP_ID: 'example.com',

        WEBAUTHN_ORIGIN: 'https://attacker.example',
      }),
    ).toThrow('WEBAUTHN_RP_ID must match or be a parent domain of WEBAUTHN_ORIGIN.');
  });

  it('does not accept a hostname suffix lookalike as the RP ID domain', () => {
    expect(() =>
      parseEnvironment({
        ...validProductionEnvironment(),

        WEBAUTHN_RP_ID: 'example.com',

        WEBAUTHN_ORIGIN: 'https://evil-example.com',
      }),
    ).toThrow('WEBAUTHN_RP_ID must match or be a parent domain of WEBAUTHN_ORIGIN.');
  });

  it.each([
    'https://user:password@vault.example.com',
    'https://vault.example.com/path',
    'https://vault.example.com?debug=true',
    'https://vault.example.com#fragment',
  ])('rejects WEBAUTHN_ORIGIN that is not a bare origin: %s', (origin) => {
    expect(() =>
      parseEnvironment({
        ...validProductionEnvironment(),

        WEBAUTHN_ORIGIN: origin,
      }),
    ).toThrow('WEBAUTHN_ORIGIN must be an origin without credentials, path, query, or fragment.');
  });

  it('continues to allow HTTP localhost configuration outside production', () => {
    const environment = parseEnvironment(validEnvironment());

    expect(environment.NODE_ENV).toBe('test');

    expect(environment.WEBAUTHN_RP_ID).toBe('localhost');

    expect(environment.WEBAUTHN_ORIGIN).toBe('http://localhost:5173');
  });
});
