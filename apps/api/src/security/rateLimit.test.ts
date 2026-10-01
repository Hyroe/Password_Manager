import express from 'express';
import request from 'supertest';

import { describe, expect, it } from 'vitest';

import {
  createAuthenticatedUserRateLimiter,
  createRateLimiter,
  type RateLimitPolicy,
} from './rateLimit.js';

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

  it('isolates authenticated rate-limit buckets by user', async () => {
    const app = express();

    const limiter = createAuthenticatedUserRateLimiter({
      identifier: 'authenticated-test',

      windowMs: 60 * 1000,

      limit: 2,
    });

    type AuthRequest = express.Request & {
      auth?: {
        sessionId: string;
        userId: string;
        email: string;
        absoluteExpiresAt: Date;
      };
    };

    app.use((req: AuthRequest, _res, next) => {
      const userId = req.get('x-test-user-id');

      if (userId) {
        req.auth = {
          sessionId: `session-${userId}`,

          userId,

          email: `${userId}@example.com`,

          absoluteExpiresAt: new Date(Date.now() + 60_000),
        };
      }

      next();
    });

    app.post('/limited', limiter, (_req, res) => {
      res.sendStatus(204);
    });

    await request(app).post('/limited').set('X-Test-User-Id', 'user-a').expect(204);

    await request(app).post('/limited').set('X-Test-User-Id', 'user-a').expect(204);

    await request(app).post('/limited').set('X-Test-User-Id', 'user-a').expect(429);

    /*
     * User B has an independent bucket even
     * when requests originate from the same IP.
     */
    await request(app).post('/limited').set('X-Test-User-Id', 'user-b').expect(204);
  });

  it('isolates authenticated rate-limit buckets by user', async () => {
    const app = express();

    const limiter = createAuthenticatedUserRateLimiter({
      identifier: 'authenticated-test',

      windowMs: 60 * 1000,

      limit: 2,
    });

    type AuthRequest = express.Request & {
      auth?: {
        sessionId: string;
        userId: string;
        email: string;
        absoluteExpiresAt: Date;
      };
    };

    app.use((req: AuthRequest, _res, next) => {
      const userId = req.get('x-test-user-id');

      if (userId) {
        req.auth = {
          sessionId: `session-${userId}`,

          userId,

          email: `${userId}@example.com`,

          absoluteExpiresAt: new Date(Date.now() + 60_000),
        };
      }

      next();
    });

    app.post('/limited', limiter, (_req, res) => {
      res.sendStatus(204);
    });

    await request(app).post('/limited').set('X-Test-User-Id', 'user-a').expect(204);

    await request(app).post('/limited').set('X-Test-User-Id', 'user-a').expect(204);

    await request(app).post('/limited').set('X-Test-User-Id', 'user-a').expect(429);

    /*
     * User B has an independent bucket even
     * when requests originate from the same IP.
     */
    await request(app).post('/limited').set('X-Test-User-Id', 'user-b').expect(204);
  });
});
