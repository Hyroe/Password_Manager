import {
  startAuthentication,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser';

import { apiRequest, clearCsrfToken, getCsrfToken } from './api';

interface LoginOptionsResponse {
  challengeId: string;

  options: PublicKeyCredentialRequestOptionsJSON;
}

export interface AuthenticatedUser {
  id: string;
  email: string;
}

export interface AuthenticatedSession {
  user: AuthenticatedUser;

  state: 'AUTHENTICATED_LOCKED';

  expiresAt?: string;

  session?: {
    absoluteExpiresAt: string;
  };
}

export async function loginWithPasskey(): Promise<AuthenticatedSession> {
  const options = await apiRequest<LoginOptionsResponse>('/api/v1/auth/passkeys/login/options', {
    method: 'POST',
    body: JSON.stringify({}),
  });

  const credential = await startAuthentication({
    optionsJSON: options.options,
  });

  const session = await apiRequest<AuthenticatedSession>('/api/v1/auth/passkeys/login/verify', {
    method: 'POST',

    body: JSON.stringify({
      challengeId: options.challengeId,

      credential,
    }),
  });

  /*
   * A successful login establishes a new
   * authoritative server session.
   */
  clearCsrfToken();

  await getCsrfToken();

  return session;
}

export async function getCurrentSession(): Promise<AuthenticatedSession> {
  const session = await apiRequest<AuthenticatedSession>('/api/v1/me');

  /*
   * A page reload destroys frontend memory,
   * so re-establish the CSRF context for the
   * still-valid HttpOnly session.
   */
  clearCsrfToken();

  await getCsrfToken();

  return session;
}

export async function logout(): Promise<void> {
  try {
    await apiRequest<void>('/api/v1/auth/logout', {
      method: 'POST',

      body: JSON.stringify({}),
    });
  } finally {
    /*
     * Never retain a token belonging to a
     * session that is being discarded.
     */
    clearCsrfToken();
  }
}
