import { prisma } from '../../lib/prisma.js';
import {
  generateSecurityToken,
  hashSecurityToken,
  verifySecurityToken,
} from '../../lib/securityTokens.js';

const EMAIL_TOKEN_TTL_MS = 15 * 60 * 1000;
const REGISTRATION_TOKEN_TTL_MS = 15 * 60 * 1000;

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export async function startRegistration(email: string) {
  const normalizedEmail = normalizeEmail(email);

  const verificationToken = generateSecurityToken();

  const attempt = await prisma.registrationAttempt.create({
    data: {
      email,
      normalizedEmail,
      emailTokenHash: Uint8Array.from(hashSecurityToken(verificationToken)),
      emailTokenExpiresAt: new Date(Date.now() + EMAIL_TOKEN_TTL_MS),
    },
    select: {
      id: true,
    },
  });

  return {
    registrationId: attempt.id,
    verificationToken,
  };
}

export async function verifyRegistrationEmail(registrationId: string, token: string) {
  const attempt = await prisma.registrationAttempt.findUnique({
    where: {
      id: registrationId,
    },
  });

  if (
    !attempt ||
    attempt.status !== 'PENDING' ||
    attempt.emailTokenExpiresAt <= new Date() ||
    !verifySecurityToken(token, attempt.emailTokenHash)
  ) {
    throw new Error('INVALID_REGISTRATION');
  }

  const existingUser = await prisma.user.findUnique({
    where: {
      normalizedEmail: attempt.normalizedEmail,
    },
    select: {
      id: true,
    },
  });

  if (existingUser) {
    throw new Error('INVALID_REGISTRATION');
  }

  const registrationToken = generateSecurityToken();

  await prisma.registrationAttempt.update({
    where: {
      id: attempt.id,
    },
    data: {
      status: 'EMAIL_VERIFIED',
      emailVerifiedAt: new Date(),
      registrationTokenHash: Uint8Array.from(hashSecurityToken(registrationToken)),
      registrationTokenExpiresAt: new Date(Date.now() + REGISTRATION_TOKEN_TTL_MS),
    },
  });

  return {
    registrationToken,
  };
}
