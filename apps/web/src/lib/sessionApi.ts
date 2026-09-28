import { apiRequest } from './api';

export interface ManagedSession {
  id: string;

  deviceLabel: string;

  createdAt: string;
  lastSeenAt: string;

  idleExpiresAt: string;
  absoluteExpiresAt: string;

  current: boolean;
}

interface ListSessionsResponse {
  sessions: ManagedSession[];
}

export async function listSessions(): Promise<ManagedSession[]> {
  const response = await apiRequest<ListSessionsResponse>('/api/v1/sessions');

  return response.sessions;
}

export async function revokeSession(sessionId: string): Promise<void> {
  await apiRequest<void>(`/api/v1/sessions/${encodeURIComponent(sessionId)}`, {
    method: 'DELETE',
  });
}

export async function revokeOtherSessions(): Promise<void> {
  await apiRequest<void>('/api/v1/sessions/revoke-others', {
    method: 'POST',

    body: JSON.stringify({}),
  });
}
