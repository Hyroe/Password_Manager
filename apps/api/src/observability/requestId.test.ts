import request from 'supertest';

import { describe, expect, it } from 'vitest';

import { createApp } from '../app.js';

describe('request IDs', () => {
  it('assigns a server-generated request ID', async () => {
    const response = await request(createApp()).get('/api/v1/health').expect(200);

    expect(response.headers['x-request-id']).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });

  it('assigns a different request ID to every request', async () => {
    const app = createApp();

    const first = await request(app).get('/api/v1/health').expect(200);

    const second = await request(app).get('/api/v1/health').expect(200);

    expect(first.headers['x-request-id']).not.toBe(second.headers['x-request-id']);
  });

  it('does not trust a client-supplied request ID', async () => {
    const clientRequestId = '11111111-1111-4111-8111-111111111111';

    const response = await request(createApp())
      .get('/api/v1/health')
      .set('X-Request-Id', clientRequestId)
      .expect(200);

    expect(response.headers['x-request-id']).not.toBe(clientRequestId);

    expect(response.headers['x-request-id']).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });

  it('assigns a request ID before security middleware rejects a request', async () => {
    const response = await request(createApp())
      .post('/api/v1/accounts')
      .set('Origin', 'https://attacker.example')
      .set('Cookie', 'pm_session=fake-session')
      .expect(403);

    expect(response.headers['x-request-id']).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });
});
