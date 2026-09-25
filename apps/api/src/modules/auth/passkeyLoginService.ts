import type { AuthenticationResponseJSON, WebAuthnCredential } from '@simplewebauthn/server';

import { SESSION_ABSOLUTE_TTL_MS, SESSION_IDLE_TTL_MS } from '../../config/session.js';

import { prisma } from '../../lib/prisma.js';

import { generateSecurityToken, hashSecurityToken } from '../../lib/securityTokens.js';

import type { PasskeyAuthenticationProvider } from './passkeyAuthenticationProvider.js';

const LOGIN_CHALLENGE_TTL_MS = 5 * 60 * 1000;

export async function createPasskeyLoginOptions(provider: PasskeyAuthenticationProvider) {
  const options = await provider.generateAuthenticationOptions();

  const challenge = await prisma.webAuthnChallenge.create({
    data: {
      purpose: 'LOGIN',
      challenge: options.challenge,

      expiresAt: new Date(Date.now() + LOGIN_CHALLENGE_TTL_MS),
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

export async function verifyPasskeyLogin(
  challengeId: string,
  response: AuthenticationResponseJSON,
  provider: PasskeyAuthenticationProvider,
) {
  const now = new Date();

  const challenge = await prisma.webAuthnChallenge.findFirst({
    where: {
      id: challengeId,
      purpose: 'LOGIN',
      usedAt: null,
    },
  });

  if (!challenge || challenge.expiresAt <= now) {
    throw new Error('AUTHENTICATION_FAILED');
  }

  const passkey = await prisma.passkeyCredential.findUnique({
    where: {
      credentialId: response.id,
    },

    include: {
      user: true,
    },
  });

  if (!passkey || passkey.user.status !== 'ACTIVE') {
    throw new Error('AUTHENTICATION_FAILED');
  }

  const credential: WebAuthnCredential = {
    id: passkey.credentialId,

    publicKey: Uint8Array.from(passkey.publicKey),

    counter: Number(passkey.counter),

    transports: passkey.transports,
  };

  let verification;

  try {
    verification = await provider.verifyAuthenticationResponse({
      response,

      expectedChallenge: challenge.challenge,

      credential,
    });
  } catch (error) {
    throw new Error('AUTHENTICATION_FAILED', {
      cause: error,
    });
  }

  const sessionToken = generateSecurityToken();

  const sessionTokenHash = Uint8Array.from(hashSecurityToken(sessionToken));

  const idleExpiresAt = new Date(now.getTime() + SESSION_IDLE_TTL_MS);

  const absoluteExpiresAt = new Date(now.getTime() + SESSION_ABSOLUTE_TTL_MS);

  await prisma.$transaction(async (tx) => {
    /*
     * Challenge is single-use.
     */
    const consumed = await tx.webAuthnChallenge.updateMany({
      where: {
        id: challenge.id,
        usedAt: null,
        expiresAt: {
          gt: now,
        },
      },

      data: {
        usedAt: now,
      },
    });

    if (consumed.count !== 1) {
      throw new Error('AUTHENTICATION_FAILED');
    }

    await tx.passkeyCredential.update({
      where: {
        id: passkey.id,
      },

      data: {
        counter: BigInt(verification.newCounter),

        lastUsedAt: now,
      },
    });

    await tx.session.create({
      data: {
        userId: passkey.user.id,

        tokenHash: sessionTokenHash,

        idleExpiresAt,
        absoluteExpiresAt,
      },
    });
  });

  return {
    sessionToken,

    user: {
      id: passkey.user.id,
      email: passkey.user.email,
    },

    absoluteExpiresAt,
  };
}
