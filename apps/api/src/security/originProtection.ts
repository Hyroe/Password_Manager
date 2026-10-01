import type { Request, RequestHandler, Response } from 'express';

import { sessionCookieName } from '../config/session.js';
import { webAuthnConfig } from '../config/webauthn.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function hasSessionCookie(req: Request): boolean {
  const cookieHeader = req.headers.cookie;

  if (!cookieHeader) {
    return false;
  }

  const cookieName = sessionCookieName();

  return cookieHeader.split(';').some((part) => part.trim().startsWith(`${cookieName}=`));
}

function rejectOrigin(res: Response): void {
  res.status(403).json({
    error: {
      code: 'FORBIDDEN',
      message: 'Request origin is not allowed.',
    },
  });
}

export function createOriginProtection(expectedOrigin = webAuthnConfig.origin): RequestHandler {
  return (req, res, next) => {
    /*
     * Safe requests do not mutate
     * server-side state.
     */
    if (SAFE_METHODS.has(req.method)) {
      next();

      return;
    }

    /*
     * B1 protects cookie-authenticated
     * browser mutations.
     *
     * Public registration/login requests
     * remain unaffected for now.
     */
    if (!hasSessionCookie(req)) {
      next();

      return;
    }

    const origin = req.get('origin');

    const fetchSite = req.get('sec-fetch-site');

    /*
     * A browser request carrying Fetch
     * Metadata but no Origin fails closed.
     */
    if (!origin) {
      if (fetchSite) {
        rejectOrigin(res);

        return;
      }

      /*
       * Non-browser HTTP clients do not
       * participate in browser CSRF.
       *
       * B2/B3 will add the independent
       * CSRF-token layer.
       */
      next();

      return;
    }

    /*
     * Exact comparison is intentional.
     *
     * No suffix matching, wildcard origins
     * or forwarded-host reconstruction.
     */
    if (origin !== expectedOrigin) {
      rejectOrigin(res);

      return;
    }

    next();
  };
}
