import request from 'supertest';
import { describe, expect, it } from 'vitest';

import { createApp } from './app.js';

const app = createApp();

describe('GET /api/v1/health', () => {
  it('returns the API health status', async () => {
    const response = await request(app).get('/api/v1/health');

    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      status: 'ok',
    });
  });
});
