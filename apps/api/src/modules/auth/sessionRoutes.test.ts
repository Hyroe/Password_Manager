import request from 'supertest';

import { afterAll, beforeEach, describe, expect, it } from 'vitest';

import { createApp } from '../../app.js';
import { SESSION_ABSOLUTE_TTL_MS, SESSION_IDLE_TTL_MS } from '../../config/session.js';
import { prisma } from '../../lib/prisma.js';

import { generateSecurityToken, hashSecurityToken } from '../../lib/securityTokens.js';

const app = createApp();

describe('authenticated sessions', () => {
  beforeEach(async () => {
    await prisma.session.deleteMany();

    await prisma.vaultKeyEnvelope.deleteMany();
    await prisma.vault.deleteMany();

    await prisma.recoveryEnvelope.deleteMany();
    await prisma.rootKeyEnvelope.deleteMany();
    await prisma.userCryptoProfile.deleteMany();

    await prisma.passkeyCredential.deleteMany();

    await prisma.accountBootstrapContext.deleteMany();
    await prisma.webAuthnChallenge.deleteMany();
    await prisma.registrationPasskey.deleteMany();

    await prisma.registrationAttempt.deleteMany();
    await prisma.user.deleteMany();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  async function createAuthenticatedSession() {
    const user = await prisma.user.create({
      data: {
        email: 'session@example.com',

        normalizedEmail: 'session@example.com',

        status: 'ACTIVE',

        emailVerifiedAt: new Date(),

        webauthnUserId: 'session-webauthn-user',
      },
    });

    const token = generateSecurityToken();

    const now = new Date();

    const session = await prisma.session.create({
      data: {
        userId: user.id,

        tokenHash: Uint8Array.from(hashSecurityToken(token)),

        idleExpiresAt: new Date(now.getTime() + SESSION_IDLE_TTL_MS),

        absoluteExpiresAt: new Date(now.getTime() + SESSION_ABSOLUTE_TTL_MS),
      },
    });

    return {
      user,
      session,
      token,
    };
  }

  it('returns the authenticated user in locked state', async () => {
    const { user, token } = await createAuthenticatedSession();

    const response = await request(app).get('/api/v1/me').set('Cookie', `pm_session=${token}`);

    expect(response.status).toBe(200);

    expect(response.body).toMatchObject({
      user: {
        id: user.id,
        email: 'session@example.com',
      },

      state: 'AUTHENTICATED_LOCKED',
    });

    expect(response.body.session.absoluteExpiresAt).toBeTypeOf('string');
  });

  it('rejects a request without a session', async () => {
    const response = await request(app).get('/api/v1/me');

    expect(response.status).toBe(401);

    expect(response.body.error.code).toBe('AUTHENTICATION_REQUIRED');
  });

  it('rejects an expired idle session', async () => {
    const { session, token } = await createAuthenticatedSession();

    await prisma.session.update({
      where: {
        id: session.id,
      },

      data: {
        idleExpiresAt: new Date(Date.now() - 1000),
      },
    });

    const response = await request(app).get('/api/v1/me').set('Cookie', `pm_session=${token}`);

    expect(response.status).toBe(401);
  });

  it('revokes the current session on logout', async () => {
    const { session, token } = await createAuthenticatedSession();

    const response = await request(app)
      .post('/api/v1/auth/logout')
      .set('Cookie', `pm_session=${token}`);

    expect(response.status).toBe(204);

    const storedSession = await prisma.session.findUniqueOrThrow({
      where: {
        id: session.id,
      },
    });

    expect(storedSession.revokedAt).not.toBeNull();

    const setCookieHeader = response.headers['set-cookie'];

    expect(setCookieHeader).toBeDefined();

    const cookies = Array.isArray(setCookieHeader)
      ? setCookieHeader.join(';')
      : (setCookieHeader ?? '');

    expect(cookies).toContain('pm_session=');

    expect(cookies).toContain('Expires=Thu, 01 Jan 1970');
  });

  it('does not accept a revoked session', async () => {
    const { session, token } = await createAuthenticatedSession();

    await prisma.session.update({
      where: {
        id: session.id,
      },

      data: {
        revokedAt: new Date(),
      },
    });

    const response = await request(app).get('/api/v1/me').set('Cookie', `pm_session=${token}`);

    expect(response.status).toBe(401);
  });
  it('lists active sessions and marks the current session', async () => {
    const { user, session: currentSession, token } = await createAuthenticatedSession();

    const secondToken = generateSecurityToken();

    const now = new Date();

    const secondSession = await prisma.session.create({
      data: {
        userId: user.id,

        tokenHash: Uint8Array.from(hashSecurityToken(secondToken)),

        idleExpiresAt: new Date(now.getTime() + SESSION_IDLE_TTL_MS),

        absoluteExpiresAt: new Date(now.getTime() + SESSION_ABSOLUTE_TTL_MS),
      },
    });

    const response = await request(app)
      .get('/api/v1/sessions')
      .set('Cookie', `pm_session=${token}`);

    expect(response.status).toBe(200);

    expect(response.body.sessions).toHaveLength(2);

    const current = response.body.sessions.find(
      (entry: { id: string }) => entry.id === currentSession.id,
    );

    const other = response.body.sessions.find(
      (entry: { id: string }) => entry.id === secondSession.id,
    );

    expect(current).toBeDefined();

    expect(current).toMatchObject({
      id: currentSession.id,
      current: true,
    });

    expect(current.createdAt).toBeTypeOf('string');
    expect(current.lastSeenAt).toBeTypeOf('string');
    expect(current.idleExpiresAt).toBeTypeOf('string');
    expect(current.absoluteExpiresAt).toBeTypeOf('string');

    expect(other).toBeDefined();

    expect(other).toMatchObject({
      id: secondSession.id,
      current: false,
    });

    expect(
      response.body.sessions.filter((entry: { current: boolean }) => entry.current),
    ).toHaveLength(1);
  });
  it('does not list revoked sessions', async () => {
    const { user, session: currentSession, token } = await createAuthenticatedSession();

    const revokedToken = generateSecurityToken();

    const now = new Date();

    const revokedSession = await prisma.session.create({
      data: {
        userId: user.id,

        tokenHash: Uint8Array.from(hashSecurityToken(revokedToken)),

        idleExpiresAt: new Date(now.getTime() + SESSION_IDLE_TTL_MS),

        absoluteExpiresAt: new Date(now.getTime() + SESSION_ABSOLUTE_TTL_MS),

        revokedAt: now,
      },
    });

    const response = await request(app)
      .get('/api/v1/sessions')
      .set('Cookie', `pm_session=${token}`);

    expect(response.status).toBe(200);

    expect(response.body.sessions).toHaveLength(1);

    expect(response.body.sessions[0]).toMatchObject({
      id: currentSession.id,
      current: true,
    });

    expect(
      response.body.sessions.some((entry: { id: string }) => entry.id === revokedSession.id),
    ).toBe(false);
  });
  it('does not list idle-expired sessions', async () => {
    const { user, session: currentSession, token } = await createAuthenticatedSession();

    const expiredToken = generateSecurityToken();

    const now = new Date();

    const expiredSession = await prisma.session.create({
      data: {
        userId: user.id,

        tokenHash: Uint8Array.from(hashSecurityToken(expiredToken)),

        idleExpiresAt: new Date(now.getTime() - 1000),

        absoluteExpiresAt: new Date(now.getTime() + SESSION_ABSOLUTE_TTL_MS),
      },
    });

    const response = await request(app)
      .get('/api/v1/sessions')
      .set('Cookie', `pm_session=${token}`);

    expect(response.status).toBe(200);

    expect(response.body.sessions).toHaveLength(1);

    expect(response.body.sessions[0].id).toBe(currentSession.id);

    expect(
      response.body.sessions.some((entry: { id: string }) => entry.id === expiredSession.id),
    ).toBe(false);
  });
  it('does not list absolute-expired sessions', async () => {
    const { user, session: currentSession, token } = await createAuthenticatedSession();

    const expiredToken = generateSecurityToken();

    const now = new Date();

    const expiredSession = await prisma.session.create({
      data: {
        userId: user.id,

        tokenHash: Uint8Array.from(hashSecurityToken(expiredToken)),

        idleExpiresAt: new Date(now.getTime() + SESSION_IDLE_TTL_MS),

        absoluteExpiresAt: new Date(now.getTime() - 1000),
      },
    });

    const response = await request(app)
      .get('/api/v1/sessions')
      .set('Cookie', `pm_session=${token}`);

    expect(response.status).toBe(200);

    expect(response.body.sessions).toHaveLength(1);

    expect(response.body.sessions[0].id).toBe(currentSession.id);

    expect(
      response.body.sessions.some((entry: { id: string }) => entry.id === expiredSession.id),
    ).toBe(false);
  });
  it('does not expose another user sessions', async () => {
    const { session: currentSession, token } = await createAuthenticatedSession();

    const otherUser = await prisma.user.create({
      data: {
        email: 'other-session@example.com',

        normalizedEmail: 'other-session@example.com',

        status: 'ACTIVE',

        emailVerifiedAt: new Date(),

        webauthnUserId: 'other-session-webauthn-user',
      },
    });

    const otherToken = generateSecurityToken();

    const now = new Date();

    const otherSession = await prisma.session.create({
      data: {
        userId: otherUser.id,

        tokenHash: Uint8Array.from(hashSecurityToken(otherToken)),

        idleExpiresAt: new Date(now.getTime() + SESSION_IDLE_TTL_MS),

        absoluteExpiresAt: new Date(now.getTime() + SESSION_ABSOLUTE_TTL_MS),
      },
    });

    const response = await request(app)
      .get('/api/v1/sessions')
      .set('Cookie', `pm_session=${token}`);

    expect(response.status).toBe(200);

    expect(response.body.sessions).toHaveLength(1);

    expect(response.body.sessions[0]).toMatchObject({
      id: currentSession.id,
      current: true,
    });

    expect(
      response.body.sessions.some((entry: { id: string }) => entry.id === otherSession.id),
    ).toBe(false);
  });
  it('requires authentication to list sessions', async () => {
    const response = await request(app).get('/api/v1/sessions');

    expect(response.status).toBe(401);

    expect(response.body.error.code).toBe('AUTHENTICATION_REQUIRED');
  });
  it('does not expose session token hashes', async () => {
    const { token } = await createAuthenticatedSession();

    const response = await request(app)
      .get('/api/v1/sessions')
      .set('Cookie', `pm_session=${token}`);

    expect(response.status).toBe(200);

    expect(response.body.sessions).toHaveLength(1);

    const serialized = JSON.stringify(response.body);

    expect(serialized).not.toContain('tokenHash');
    expect(serialized).not.toContain('token_hash');

    expect(Object.keys(response.body.sessions[0]).sort()).toEqual(
      ['absoluteExpiresAt', 'createdAt', 'current', 'id', 'idleExpiresAt', 'lastSeenAt'].sort(),
    );
  });
});
