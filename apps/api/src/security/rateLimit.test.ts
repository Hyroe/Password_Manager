import express from 'express';
import request from 'supertest';

import { describe, expect, it } from 'vitest';

import { createRateLimiter, type RateLimitPolicy } from './rateLimit.js';

const testPolicy: RateLimitPolicy = {
  identifier: 'test-rate-limit',

  windowMs: 60 * 1000,

  limit: 2,
};

function createTestApp() {
  const app = express();

  app.get(
    '/limited',

    createRateLimiter(testPolicy),

    (_req, res) => {
      res.status(200).json({
        ok: true,
      });
    },
  );

  return app;
}

describe('rate-limit infrastructure', () => {
  it('allows requests below the configured limit', async () => {
    const app = createTestApp();

    await request(app).get('/limited').expect(200);

    await request(app).get('/limited').expect(200);
  });

  it('returns the stable API error after the limit is exceeded', async () => {
    const app = createTestApp();

    await request(app).get('/limited').expect(200);

    await request(app).get('/limited').expect(200);

    const response = await request(app).get('/limited').expect(429);

    expect(response.body).toEqual({
      error: {
        code: 'RATE_LIMITED',

        message: 'Too many requests. Try again later.',
      },
    });
  });

  it('exposes standardized rate-limit metadata without legacy headers', async () => {
    const app = createTestApp();

    const response = await request(app).get('/limited').expect(200);

    expect(response.headers['ratelimit']).toBeDefined();

    expect(response.headers['x-ratelimit-limit']).toBeUndefined();

    expect(response.headers['x-ratelimit-remaining']).toBeUndefined();
  });

  it('includes retry metadata when blocking a request', async () => {
    const app = createTestApp();

    await request(app).get('/limited').expect(200);

    await request(app).get('/limited').expect(200);

    const response = await request(app).get('/limited').expect(429);

    expect(response.headers['retry-after']).toBeDefined();
  });
});
