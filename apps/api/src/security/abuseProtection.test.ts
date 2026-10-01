import request from 'supertest';

import { describe, expect, it } from 'vitest';

import { createApp } from '../app.js';

describe('abuse protection', () => {
  it('rate limits registration start with the stable API error', async () => {
    const app = createApp();

    /*
     * Invalid payloads deliberately stop before
     * any database access while still exercising
     * the real route-level rate limiter.
     */
    for (let requestNumber = 0; requestNumber < 10; requestNumber += 1) {
      await request(app).post('/api/v1/accounts').send({}).expect(400);
    }

    const blocked = await request(app).post('/api/v1/accounts').send({}).expect(429);

    expect(blocked.body).toEqual({
      error: {
        code: 'RATE_LIMITED',

        message: 'Too many requests. Try again later.',
      },
    });

    expect(blocked.headers['retry-after']).toBeDefined();
  });

  it('keeps registration endpoint buckets independent', async () => {
    const app = createApp();

    for (let requestNumber = 0; requestNumber < 10; requestNumber += 1) {
      await request(app).post('/api/v1/accounts').send({}).expect(400);
    }

    await request(app).post('/api/v1/accounts').send({}).expect(429);

    /*
     * Exhausting registration-start must not
     * consume the verification bucket.
     */
    const verification = await request(app)
      .post('/api/v1/accounts/verify-email')
      .send({})
      .expect(400);

    expect(verification.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('rate limits passkey verification independently', async () => {
    const app = createApp();

    /*
     * login/verify permits 60 attempts in its
     * initial operational window.
     *
     * Invalid payloads avoid WebAuthn and DB work.
     */
    for (let requestNumber = 0; requestNumber < 60; requestNumber += 1) {
      await request(app).post('/api/v1/auth/passkeys/login/verify').send({}).expect(400);
    }

    const blocked = await request(app)
      .post('/api/v1/auth/passkeys/login/verify')
      .send({})
      .expect(429);

    expect(blocked.body.error.code).toBe('RATE_LIMITED');

    expect(blocked.headers['retry-after']).toBeDefined();

    /*
     * Registration verification has a separate
     * limiter and therefore remains reachable.
     */
    const registrationVerify = await request(app)
      .post('/api/v1/auth/passkeys/register/verify')
      .send({})
      .expect(400);

    expect(registrationVerify.body.error.code).toBe('VALIDATION_ERROR');
  });
});
