import express from 'express';
import request from 'supertest';

import { describe, expect, it } from 'vitest';

import { deriveCsrfToken } from './csrfToken.js';

import { requireCsrfForBrowserMutation } from './csrfMiddleware.js';

function createTestApp() {
  const app = express();

  app.use(requireCsrfForBrowserMutation);

  app.all('/test', (_req, res) => {
    res.sendStatus(204);
  });

  return app;
}

describe('CSRF browser mutation protection', () => {
  it('allows safe requests', async () => {
    const response = await request(createTestApp())
      .get('/test')
      .set('Cookie', 'pm_session=session-a')
      .set('Origin', 'http://localhost:5173');

    expect(response.status).toBe(204);
  });

  it('allows public mutations without a session cookie', async () => {
    const response = await request(createTestApp())
      .post('/test')
      .set('Origin', 'http://localhost:5173');

    expect(response.status).toBe(204);
  });

  it('rejects authenticated browser mutations without a CSRF token', async () => {
    const response = await request(createTestApp())
      .post('/test')
      .set('Cookie', 'pm_session=session-a')
      .set('Origin', 'http://localhost:5173');

    expect(response.status).toBe(403);

    expect(response.body.error.code).toBe('INVALID_CSRF');
  });

  it('rejects an invalid CSRF token', async () => {
    const response = await request(createTestApp())
      .post('/test')
      .set('Cookie', 'pm_session=session-a')
      .set('Origin', 'http://localhost:5173')
      .set('X-CSRF-Token', 'invalid');

    expect(response.status).toBe(403);
  });

  it('rejects a token belonging to another session', async () => {
    const token = deriveCsrfToken('session-b');

    const response = await request(createTestApp())
      .post('/test')
      .set('Cookie', 'pm_session=session-a')
      .set('Origin', 'http://localhost:5173')
      .set('X-CSRF-Token', token);

    expect(response.status).toBe(403);
  });

  it('allows a correctly bound CSRF token', async () => {
    const sessionToken = 'session-a';

    const response = await request(createTestApp())
      .post('/test')
      .set('Cookie', `pm_session=${sessionToken}`)
      .set('Origin', 'http://localhost:5173')
      .set('X-CSRF-Token', deriveCsrfToken(sessionToken));

    expect(response.status).toBe(204);
  });

  it('preserves direct non-browser API clients', async () => {
    const response = await request(createTestApp())
      .post('/test')
      .set('Cookie', 'pm_session=session-a');

    expect(response.status).toBe(204);
  });
});
