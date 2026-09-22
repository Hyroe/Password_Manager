import { randomBytes } from 'node:crypto';

import type { RegistrationResponseJSON } from '@simplewebauthn/server';

import { prisma } from '../../lib/prisma.js';
import {
  generateSecurityToken,
  hashSecurityToken,
  verifySecurityToken,
} from '../../lib/securityTokens.js';
import type { WebAuthnProvider } from './webauthnProvider.js';

const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const BOOTSTRAP_TOKEN_TTL_MS = 15 * 60 * 1000;

function createWebAuthnUserId(): string {
  return randomBytes(32).toString('base64url');
}

async function getEligibleRegistration(registrationId: string, registrationToken: string) {
  const attempt = await prisma.registrationAttempt.findUnique({
    where: {
      id: registrationId,
    },
  });

  if (
    !attempt ||
    attempt.status !== 'EMAIL_VERIFIED' ||
    !attempt.registrationTokenHash ||
    !attempt.registrationTokenExpiresAt ||
    attempt.registrationTokenExpiresAt <= new Date() ||
    !verifySecurityToken(registrationToken, attempt.registrationTokenHash)
  ) {
    throw new Error('INVALID_REGISTRATION');
  }

  return attempt;
}

export async function createPasskeyRegistrationOptions(
  registrationId: string,
  registrationToken: string,
  provider: WebAuthnProvider,
) {
  let attempt = await getEligibleRegistration(registrationId, registrationToken);

  if (!attempt.webauthnUserId) {
    attempt = await prisma.registrationAttempt.update({
      where: {
        id: attempt.id,
      },
      data: {
        webauthnUserId: createWebAuthnUserId(),
      },
    });
  }

  const webauthnUserId = attempt.webauthnUserId;

  if (!webauthnUserId) {
    throw new Error('INVALID_REGISTRATION');
  }

  const options = await provider.generateRegistrationOptions({
    userName: attempt.email,
    userDisplayName: attempt.email,
    userID: Buffer.from(webauthnUserId, 'base64url'),
  });

  const challenge = await prisma.webAuthnChallenge.create({
    data: {
      registrationAttemptId: attempt.id,
      purpose: 'REGISTER_PASSKEY',
      challenge: options.challenge,
      expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS),
    },
    select: {
      id: true,
    },
  });

  return {
    challengeId: challenge.id,
    options,
  };
}

export async function verifyPasskeyRegistration(
  registrationId: string,
  registrationToken: string,
  challengeId: string,
  credential: RegistrationResponseJSON,
  provider: WebAuthnProvider,
) {
  const attempt = await getEligibleRegistration(registrationId, registrationToken);

  if (!attempt.webauthnUserId) {
    throw new Error('INVALID_REGISTRATION');
  }

  const challenge = await prisma.webAuthnChallenge.findFirst({
    where: {
      id: challengeId,
      registrationAttemptId: attempt.id,
      purpose: 'REGISTER_PASSKEY',
      usedAt: null,
    },
  });

  if (!challenge || challenge.expiresAt <= new Date()) {
    throw new Error('INVALID_CHALLENGE');
  }

  const verification = await provider.verifyRegistrationResponse({
    response: credential,
    expectedChallenge: challenge.challenge,
  });

  const bootstrapToken = generateSecurityToken();
  const now = new Date();

  await prisma.$transaction(async (tx) => {
    const consumed = await tx.webAuthnChallenge.updateMany({
      where: {
        id: challenge.id,
        usedAt: null,
      },
      data: {
        usedAt: now,
      },
    });

    if (consumed.count !== 1) {
      throw new Error('INVALID_CHALLENGE');
    }

    const webauthnUserId = attempt.webauthnUserId;

    if (!webauthnUserId) {
      throw new Error('INVALID_REGISTRATION');
    }

    await tx.registrationPasskey.create({
      data: {
        registrationAttemptId: attempt.id,

        credentialId: verification.credential.id,
        publicKey: Buffer.from(verification.credential.publicKey),
        counter: BigInt(verification.credential.counter),

        webauthnUserId,

        deviceType: verification.deviceType,
        backedUp: verification.backedUp,

        transports: verification.credential.transports ?? [],
      },
    });

    await tx.registrationAttempt.update({
      where: {
        id: attempt.id,
      },
      data: {
        status: 'PASSKEY_REGISTERED',

        bootstrapTokenHash: Uint8Array.from(hashSecurityToken(bootstrapToken)),
        bootstrapTokenExpiresAt: new Date(Date.now() + BOOTSTRAP_TOKEN_TTL_MS),
      },
    });
  });

  return {
    bootstrapToken,
  };
}
