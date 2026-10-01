import type { RequestHandler } from 'express';
import helmet from 'helmet';

export function createHttpSecurityHeaders(): RequestHandler {
  const isProduction = process.env.NODE_ENV === 'production';

  return helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],

        baseUri: ["'none'"],

        connectSrc: ["'self'"],

        fontSrc: ["'self'"],

        formAction: ["'self'"],

        frameAncestors: ["'none'"],

        imgSrc: ["'self'", 'data:'],

        manifestSrc: ["'self'"],

        objectSrc: ["'none'"],

        scriptSrc: ["'self'", "'wasm-unsafe-eval'"],

        scriptSrcAttr: ["'none'"],

        styleSrc: ["'self'"],

        workerSrc: ["'self'"],

        upgradeInsecureRequests: isProduction ? [] : null,
      },
    },

    /*
     * Keep localhost/test HTTP usable.
     *
     * Production receives HSTS, but we
     * deliberately do not claim all
     * subdomains yet. That decision belongs
     * to final deployment configuration.
     */
    strictTransportSecurity: isProduction
      ? {
          maxAge: 31_536_000,
          includeSubDomains: false,
          preload: false,
        }
      : false,

    referrerPolicy: {
      policy: 'no-referrer',
    },

    crossOriginOpenerPolicy: {
      policy: 'same-origin',
    },

    crossOriginResourcePolicy: {
      policy: 'same-origin',
    },

    xFrameOptions: {
      action: 'deny',
    },
  });
}

export const permissionsPolicy: RequestHandler = (_req, res, next) => {
  res.setHeader(
    'Permissions-Policy',
    ['camera=()', 'geolocation=()', 'microphone=()', 'payment=()', 'usb=()'].join(', '),
  );

  next();
};
