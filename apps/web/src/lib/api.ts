interface ApiErrorResponse {
  error?: {
    code?: string;
    message?: string;
  };
}

interface CsrfTokenResponse {
  csrfToken: string;
}

let cachedCsrfToken: string | null = null;

let csrfTokenRequest: Promise<string> | null = null;

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export class ApiError extends Error {
  readonly status: number;
  readonly code: string | undefined;

  constructor(message: string, status: number, code?: string) {
    super(message);

    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

export function clearCsrfToken(): void {
  cachedCsrfToken = null;
  csrfTokenRequest = null;
}

export async function getCsrfToken(): Promise<string> {
  if (cachedCsrfToken) {
    return cachedCsrfToken;
  }

  if (csrfTokenRequest) {
    return csrfTokenRequest;
  }

  csrfTokenRequest = (async () => {
    const response = await fetch('/api/v1/auth/csrf', {
      method: 'GET',

      credentials: 'same-origin',

      headers: {
        Accept: 'application/json',
      },
    });

    const body = (await response.json().catch(() => undefined)) as
      ApiErrorResponse | CsrfTokenResponse | undefined;

    if (!response.ok) {
      if (response.status === 401) {
        clearCsrfToken();
      }

      const error = body as ApiErrorResponse | undefined;

      throw new ApiError(
        error?.error?.message ?? `Request failed with status ${response.status}`,

        response.status,

        error?.error?.code,
      );
    }

    const csrfResponse = body as CsrfTokenResponse | undefined;

    if (
      !csrfResponse ||
      typeof csrfResponse.csrfToken !== 'string' ||
      csrfResponse.csrfToken.length === 0
    ) {
      throw new Error('Invalid CSRF token response.');
    }

    cachedCsrfToken = csrfResponse.csrfToken;

    return cachedCsrfToken;
  })();

  try {
    return await csrfTokenRequest;
  } finally {
    csrfTokenRequest = null;
  }
}

export async function apiRequest<T>(url: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);

  const method = (init?.method ?? 'GET').toUpperCase();

  if (!SAFE_METHODS.has(method) && cachedCsrfToken && !headers.has('X-CSRF-Token')) {
    headers.set('X-CSRF-Token', cachedCsrfToken);
  }

  if (init?.body !== undefined && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(url, {
    ...init,
    headers,
    credentials: 'same-origin',
  });

  if (response.status === 204) {
    return undefined as T;
  }

  const body = (await response.json().catch(() => undefined)) as ApiErrorResponse | T | undefined;

  if (!response.ok) {
    const error = body as ApiErrorResponse | undefined;

    if (response.status === 401) {
      clearCsrfToken();
    }

    if (response.status === 403 && error?.error?.code === 'INVALID_CSRF') {
      clearCsrfToken();
    }

    throw new ApiError(
      error?.error?.message ?? `Request failed with status ${response.status}`,

      response.status,

      error?.error?.code,
    );
  }

  return body as T;
}
