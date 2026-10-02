import express from 'express';
import request from 'supertest';

import { describe, expect, it } from 'vitest';

import { createApp } from '../app.js';

import { createErrorHandler } from './errorHandler.js';

import { createHttpRequestLoggingMiddleware } from './httpRequestLogging.js';

import type { StructuredLogEvent, StructuredLogger } from './logger.js';

import { createRequestIdMiddleware } from './requestId.js';

function createMemoryLogger() {
  const events: StructuredLogEvent[] = [];

  const logger: StructuredLogger = {
    write(event) {
      events.push(event);
    },
  };

  return {
    events,
    logger,
  };
}

describe('safe API error handling', () => {
  it('redacts unexpected internal errors', async () => {
    const { events, logger } = createMemoryLogger();

    const secret = 'database-password-super-secret';

    const app = express();

    app.use(createRequestIdMiddleware());

    app.use(createHttpRequestLoggingMiddleware(logger));

    app.get('/boom', () => {
      throw new Error(`Database connection failed: ${secret}`);
    });

    app.use(createErrorHandler(logger));

    const response = await request(app).get('/boom').expect(500);

    expect(response.body).toEqual({
      error: {
        code: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred.',
        requestId: response.headers['x-request-id'],
      },
    });

    expect(JSON.stringify(response.body)).not.toContain(secret);

    expect(JSON.stringify(events)).not.toContain(secret);

    const errorEvent = events.find((event) => event.event === 'http.request.error');

    expect(errorEvent).toMatchObject({
      level: 'error',
      event: 'http.request.error',
      requestId: response.headers['x-request-id'],
      statusCode: 500,
      code: 'INTERNAL_ERROR',
    });
  });

  it('returns a safe error for malformed JSON', async () => {
    const { events, logger } = createMemoryLogger();

    const response = await request(
      createApp({
        logger,
      }),
    )
      .post('/api/v1/accounts')
      .set('Content-Type', 'application/json')
      .send('{"broken":')
      .expect(400);

    expect(response.body).toEqual({
      error: {
        code: 'INVALID_JSON',
        message: 'Request body contains invalid JSON.',
        requestId: response.headers['x-request-id'],
      },
    });

    expect(
      events.some((event) => event.event === 'http.request.error' && event.code === 'INVALID_JSON'),
    ).toBe(true);
  });

  it('returns a safe error for oversized request bodies', async () => {
    const { events, logger } = createMemoryLogger();

    const app = express();

    app.use(createRequestIdMiddleware());

    app.use(createHttpRequestLoggingMiddleware(logger));

    app.use(
      express.json({
        limit: '10b',
      }),
    );

    app.post('/payload', (_req, res) => {
      res.sendStatus(204);
    });

    app.use(createErrorHandler(logger));

    const response = await request(app)
      .post('/payload')
      .send({
        value: 'this-is-larger-than-ten-bytes',
      })
      .expect(413);

    expect(response.body).toEqual({
      error: {
        code: 'PAYLOAD_TOO_LARGE',
        message: 'Request body is too large.',
        requestId: response.headers['x-request-id'],
      },
    });

    expect(
      events.some(
        (event) => event.event === 'http.request.error' && event.code === 'PAYLOAD_TOO_LARGE',
      ),
    ).toBe(true);
  });
});
