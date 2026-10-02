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
});
