import { SESSION_IDLE_TTL_MS, SESSION_TOUCH_INTERVAL_MS } from '../../config/session.js';

import { prisma } from '../../lib/prisma.js';

import { hashSecurityToken } from '../../lib/securityTokens.js';

export interface ActiveSession {
  sessionId: string;
  userId: string;
  email: string;
  absoluteExpiresAt: Date;
}

function tokenHashForPrisma(token: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(hashSecurityToken(token));
}

export async function resolveSession(sessionToken: string): Promise<ActiveSession | null> {
  const now = new Date();

  const session = await prisma.session.findUnique({
    where: {
      tokenHash: tokenHashForPrisma(sessionToken),
    },

    include: {
      user: true,
    },
  });

  if (
    !session ||
    session.revokedAt ||
    session.idleExpiresAt <= now ||
    session.absoluteExpiresAt <= now ||
    session.user.status !== 'ACTIVE'
  ) {
    return null;
  }

  /*
   * Avoid one DB write for every API request.
   * Refresh idle expiration only periodically.
   */
  if (now.getTime() - session.lastSeenAt.getTime() >= SESSION_TOUCH_INTERVAL_MS) {
    const proposedIdleExpiration = new Date(now.getTime() + SESSION_IDLE_TTL_MS);

    const idleExpiresAt =
      proposedIdleExpiration < session.absoluteExpiresAt
        ? proposedIdleExpiration
        : session.absoluteExpiresAt;

    await prisma.session.updateMany({
      where: {
        id: session.id,
        revokedAt: null,

        idleExpiresAt: {
          gt: now,
        },

        absoluteExpiresAt: {
          gt: now,
        },
      },

      data: {
        lastSeenAt: now,
        idleExpiresAt,
      },
    });
  }

  return {
    sessionId: session.id,
    userId: session.user.id,
    email: session.user.email,

    absoluteExpiresAt: session.absoluteExpiresAt,
  };
}

export async function revokeSession(sessionId: string): Promise<void> {
  await prisma.session.updateMany({
    where: {
      id: sessionId,
      revokedAt: null,
    },

    data: {
      revokedAt: new Date(),
    },
  });
}

export interface ListedSession {
  id: string;

  createdAt: Date;
  lastSeenAt: Date;

  idleExpiresAt: Date;
  absoluteExpiresAt: Date;

  current: boolean;
}

export async function listActiveSessions(
  userId: string,
  currentSessionId: string,
): Promise<ListedSession[]> {
  const now = new Date();

  const sessions = await prisma.session.findMany({
    where: {
      userId,

      revokedAt: null,

      idleExpiresAt: {
        gt: now,
      },

      absoluteExpiresAt: {
        gt: now,
      },
    },

    orderBy: {
      createdAt: 'desc',
    },

    select: {
      id: true,

      createdAt: true,
      lastSeenAt: true,

      idleExpiresAt: true,
      absoluteExpiresAt: true,
    },
  });

  return sessions.map((session) => ({
    ...session,

    current: session.id === currentSessionId,
  }));
}

export async function revokeUserSession(userId: string, sessionId: string): Promise<boolean> {
  const result = await prisma.session.updateMany({
    where: {
      id: sessionId,
      userId,
      revokedAt: null,
    },

    data: {
      revokedAt: new Date(),
    },
  });

  return result.count === 1;
}

export async function revokeOtherSessions(
  userId: string,
  currentSessionId: string,
): Promise<number> {
  const result = await prisma.session.updateMany({
    where: {
      userId,

      id: {
        not: currentSessionId,
      },

      revokedAt: null,
    },

    data: {
      revokedAt: new Date(),
    },
  });

  return result.count;
}
