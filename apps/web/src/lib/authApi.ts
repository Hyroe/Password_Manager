import {
  startAuthentication,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser';

import { apiRequest } from './api';

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

  return apiRequest<AuthenticatedSession>('/api/v1/auth/passkeys/login/verify', {
    method: 'POST',

    body: JSON.stringify({
      challengeId: options.challengeId,

      credential,
    }),
  });
}

export async function getCurrentSession(): Promise<AuthenticatedSession> {
  return apiRequest<AuthenticatedSession>('/api/v1/me');
}

export async function logout(): Promise<void> {
  await apiRequest<void>('/api/v1/auth/logout', {
    method: 'POST',
    body: JSON.stringify({}),
  });
}
