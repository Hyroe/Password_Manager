import request from 'supertest';

import { describe, expect, it } from 'vitest';

import { createApp } from '../app.js';

import type { StructuredLogEvent, StructuredLogger } from './logger.js';

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

describe('HTTP request logging', () => {
  it('logs safe request completion metadata', async () => {
    const { events, logger } = createMemoryLogger();

    const response = await request(
      createApp({
        logger,
      }),
    )
      .get('/api/v1/health')
      .expect(200);

    expect(events).toHaveLength(1);

    expect(events[0]).toMatchObject({
      level: 'info',
      event: 'http.request.completed',
      requestId: response.headers['x-request-id'],
      method: 'GET',
      path: '/api/v1/health',
      statusCode: 200,
    });

    if (events[0].event === 'http.request.completed') {
      expect(events[0].durationMs).toBeGreaterThanOrEqual(0);

      expect(Number.isInteger(events[0].durationMs)).toBe(true);

      expect(Number.isNaN(Date.parse(events[0].timestamp))).toBe(false);
    }
  });

  it('does not log query strings, headers, cookies, or request bodies', async () => {
    const { events, logger } = createMemoryLogger();

    const headerSecret = 'header-secret-value';

    const cookieSecret = 'cookie-secret-value';

    const querySecret = 'query-secret-value';

    const bodySecret = 'body-secret-value';

    await request(
      createApp({
        logger,
      }),
    )
      .post(`/api/v1/accounts?token=${querySecret}`)
      .set('Authorization', `Bearer ${headerSecret}`)
      .set('Cookie', `pm_session=${cookieSecret}`)
      .send({
        password: bodySecret,
      });

    expect(events).toHaveLength(1);

    const serialized = JSON.stringify(events[0]);

    expect(serialized).not.toContain(headerSecret);

    expect(serialized).not.toContain(cookieSecret);

    expect(serialized).not.toContain(querySecret);

    expect(serialized).not.toContain(bodySecret);

    expect(events[0]).toMatchObject({
      event: 'http.request.completed',
      method: 'POST',
      path: '/api/v1/accounts',
    });
  });

  it('logs security rejections with the same request ID returned to the client', async () => {
    const { events, logger } = createMemoryLogger();

    const response = await request(
      createApp({
        logger,
      }),
    )
      .post('/api/v1/accounts')
      .set('Origin', 'https://attacker.example')
      .set('Cookie', 'pm_session=fake-session')
      .expect(403);

    expect(events).toHaveLength(1);

    expect(events[0]).toMatchObject({
      event: 'http.request.completed',
      requestId: response.headers['x-request-id'],
      method: 'POST',
      path: '/api/v1/accounts',
      statusCode: 403,
    });
  });
});
