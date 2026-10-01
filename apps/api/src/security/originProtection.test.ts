import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';

import { createOriginProtection } from './originProtection.js';

const TRUSTED_ORIGIN = 'http://localhost:5173';

function createTestApp() {
  const app = express();

  app.use(createOriginProtection(TRUSTED_ORIGIN));

  app.all('/test', (_req, res) => {
    res.sendStatus(204);
  });

  return app;
}

describe('authenticated browser origin protection', () => {
  it('allows safe methods regardless of origin', async () => {
    const response = await request(createTestApp())
      .get('/test')
      .set('Cookie', 'pm_session=test-session')
      .set('Origin', 'https://attacker.example');

    expect(response.status).toBe(204);
  });

  it('does not apply authenticated origin policy without a session cookie', async () => {
    const response = await request(createTestApp())
      .post('/test')
      .set('Origin', 'https://attacker.example');

    expect(response.status).toBe(204);
  });

  it('allows an authenticated mutation from the exact trusted origin', async () => {
    const response = await request(createTestApp())
      .post('/test')
      .set('Cookie', 'pm_session=test-session')
      .set('Origin', TRUSTED_ORIGIN);

    expect(response.status).toBe(204);
  });

  it('rejects an authenticated mutation from another origin', async () => {
    const response = await request(createTestApp())
      .post('/test')
      .set('Cookie', 'pm_session=test-session')
      .set('Origin', 'https://attacker.example');

    expect(response.status).toBe(403);

    expect(response.body).toEqual({
      error: {
        code: 'FORBIDDEN',
        message: 'Request origin is not allowed.',
      },
    });
  });

  it('rejects origin lookalikes', async () => {
    const response = await request(createTestApp())
      .post('/test')
      .set('Cookie', 'pm_session=test-session')
      .set('Origin', 'http://localhost:5173.attacker.example');

    expect(response.status).toBe(403);
  });

  it('rejects browser mutations that omit Origin', async () => {
    const response = await request(createTestApp())
      .post('/test')
      .set('Cookie', 'pm_session=test-session')
      .set('Sec-Fetch-Site', 'same-origin');

    expect(response.status).toBe(403);
  });

  it('allows non-browser clients without browser origin metadata', async () => {
    const response = await request(createTestApp())
      .post('/test')
      .set('Cookie', 'pm_session=test-session');

    expect(response.status).toBe(204);
  });
});
