import { randomUUID } from 'node:crypto';

import type { RequestHandler, Response } from 'express';

export const REQUEST_ID_HEADER = 'X-Request-Id';

export function createRequestIdMiddleware(): RequestHandler {
  return (_req, res, next) => {
    const requestId = randomUUID();

    res.locals.requestId = requestId;

    res.setHeader(REQUEST_ID_HEADER, requestId);

    next();
  };
}

export function getRequestId(res: Response): string | undefined {
  const requestId = res.locals.requestId;

  return typeof requestId === 'string' ? requestId : undefined;
}
