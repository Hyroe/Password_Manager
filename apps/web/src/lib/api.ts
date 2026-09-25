interface ApiErrorResponse {
  error?: {
    code?: string;
    message?: string;
  };
}

export async function apiRequest<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...init,

    credentials: 'same-origin',

    headers: {
      'Content-Type': 'application/json',
      ...init?.headers,
    },
  });

  if (response.status === 204) {
    return undefined as T;
  }

  const body = (await response.json().catch(() => undefined)) as ApiErrorResponse | T | undefined;

  if (!response.ok) {
    const errorBody = body as ApiErrorResponse | undefined;

    throw new Error(errorBody?.error?.message ?? `Request failed with status ${response.status}`);
  }

  return body as T;
}
