import type { ErrorRequestHandler } from 'express';

import type { StructuredLogger } from './logger.js';

import { getRequestId } from './requestId.js';

interface ParserError {
  type?: unknown;
}

interface SafeErrorResponse {
  statusCode: number;
  code: 'INVALID_JSON' | 'PAYLOAD_TOO_LARGE' | 'INTERNAL_ERROR';
  message: string;
  level: 'warn' | 'error';
}

function classifyError(error: unknown): SafeErrorResponse {
  const parserError = error as ParserError;

  if (parserError?.type === 'entity.parse.failed') {
    return {
      statusCode: 400,
      code: 'INVALID_JSON',
      message: 'Request body contains invalid JSON.',
      level: 'warn',
    };
  }

  if (parserError?.type === 'entity.too.large') {
    return {
      statusCode: 413,
      code: 'PAYLOAD_TOO_LARGE',
      message: 'Request body is too large.',
      level: 'warn',
    };
  }

  return {
    statusCode: 500,
    code: 'INTERNAL_ERROR',
    message: 'An unexpected error occurred.',
    level: 'error',
  };
}

export function createErrorHandler(logger: StructuredLogger): ErrorRequestHandler {
  return (error, _req, res, next) => {
    if (res.headersSent) {
      next(error);
      return;
    }

    const requestId = getRequestId(res);

    const safeError = classifyError(error);

    if (requestId) {
      logger.write({
        timestamp: new Date().toISOString(),
        level: safeError.level,
        event: 'http.request.error',
        requestId,
        statusCode: safeError.statusCode,
        code: safeError.code,
      });
    }

    res.status(safeError.statusCode).json({
      error: {
        code: safeError.code,

        message: safeError.message,

        ...(requestId ? { requestId } : {}),
      },
    });
  };
}
