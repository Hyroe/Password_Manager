import type { RequestHandler } from 'express';

import type { StructuredLogger } from './logger.js';
import { getRequestId } from './requestId.js';

export function createHttpRequestLoggingMiddleware(logger: StructuredLogger): RequestHandler {
  return (req, res, next) => {
    const startedAt = process.hrtime.bigint();

    /*
     * Capture the path before Express enters
     * mounted routers. Router traversal can
     * temporarily rewrite req.url/req.path.
     *
     * req.path intentionally excludes the
     * query string.
     */
    const method = req.method;
    const path = req.path;

    res.on('finish', () => {
      const requestId = getRequestId(res);

      if (!requestId) {
        return;
      }

      const elapsedNanoseconds = process.hrtime.bigint() - startedAt;

      const durationMs = Number(elapsedNanoseconds) / 1_000_000;

      logger.write({
        timestamp: new Date().toISOString(),
        level: 'info',
        event: 'http.request.completed',
        requestId,
        method,
        path,
        statusCode: res.statusCode,
        durationMs: Math.round(durationMs),
      });
    });

    next();
  };
}
