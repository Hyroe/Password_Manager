import { createHmac, timingSafeEqual } from 'node:crypto';

const CSRF_TOKEN_CONTEXT = 'pm:csrf:v1';

function deriveCsrfTokenBytes(sessionToken: string): Buffer {
  return createHmac('sha256', Buffer.from(sessionToken, 'utf8'))
    .update(CSRF_TOKEN_CONTEXT, 'utf8')
    .digest();
}

export function deriveCsrfToken(sessionToken: string): string {
  return deriveCsrfTokenBytes(sessionToken).toString('base64url');
}

export function verifyCsrfToken(sessionToken: string, candidateToken: string): boolean {
  const expected = deriveCsrfTokenBytes(sessionToken);

  const candidate = Buffer.from(candidateToken, 'base64url');

  if (candidate.length !== expected.length) {
    return false;
  }

  return timingSafeEqual(candidate, expected);
}
