import { describe, expect, it } from 'vitest';

import { resolveRuntimeRedirect } from './runtimeRouting';

describe('runtime routing', () => {
  it('does not redirect while checking the session', () => {
    expect(resolveRuntimeRedirect('CHECKING_SESSION', '/vault')).toBeNull();
  });

  it('does not redirect while session availability is unknown', () => {
    expect(resolveRuntimeRedirect('SESSION_UNAVAILABLE', '/settings/security')).toBeNull();
  });

  it('allows signed-out users to access login and registration', () => {
    expect(resolveRuntimeRedirect('SIGNED_OUT', '/login')).toBeNull();

    expect(resolveRuntimeRedirect('SIGNED_OUT', '/register')).toBeNull();
  });

  it('redirects signed-out users away from authenticated routes', () => {
    expect(resolveRuntimeRedirect('SIGNED_OUT', '/vault')).toBe('/login');

    expect(resolveRuntimeRedirect('SIGNED_OUT', '/settings/security')).toBe('/login');

    expect(resolveRuntimeRedirect('SIGNED_OUT', '/recovery')).toBe('/login');
  });

  it('allows locked authenticated users to access locked routes', () => {
    expect(resolveRuntimeRedirect('AUTHENTICATED_LOCKED', '/vault')).toBeNull();

    expect(resolveRuntimeRedirect('AUTHENTICATED_LOCKED', '/settings/security')).toBeNull();

    expect(resolveRuntimeRedirect('AUTHENTICATED_LOCKED', '/recovery')).toBeNull();
  });

  it('prevents locked users from accessing decrypted vault item routes', () => {
    expect(resolveRuntimeRedirect('AUTHENTICATED_LOCKED', '/vault/items/item-123')).toBe('/vault');
  });

  it('redirects authenticated users away from authentication routes', () => {
    expect(resolveRuntimeRedirect('AUTHENTICATED_LOCKED', '/login')).toBe('/vault');

    expect(resolveRuntimeRedirect('UNLOCKED', '/register')).toBe('/vault');
  });

  it('allows unlocked users to access vault item routes', () => {
    expect(resolveRuntimeRedirect('UNLOCKED', '/vault')).toBeNull();

    expect(resolveRuntimeRedirect('UNLOCKED', '/vault/items/item-123')).toBeNull();

    expect(resolveRuntimeRedirect('UNLOCKED', '/settings/security')).toBeNull();
  });

  it('redirects unlocked users away from recovery', () => {
    expect(resolveRuntimeRedirect('UNLOCKED', '/recovery')).toBe('/vault');
  });

  it('redirects unknown paths according to authentication state', () => {
    expect(resolveRuntimeRedirect('SIGNED_OUT', '/does-not-exist')).toBe('/login');

    expect(resolveRuntimeRedirect('AUTHENTICATED_LOCKED', '/does-not-exist')).toBe('/vault');

    expect(resolveRuntimeRedirect('UNLOCKED', '/does-not-exist')).toBe('/vault');
  });
});
