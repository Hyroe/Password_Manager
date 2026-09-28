import type { Request, Response } from 'express';

import { sessionCookieClearOptions, sessionCookieName } from '../../config/session.js';

import { completeMasterPasswordRecoverySchema } from './vaultRecoverySchemas.js';

import {
  completeMasterPasswordRecovery,
  getMasterPasswordRecoveryMaterial,
  getVaultUnlockMaterial,
} from './vaultUnlockService.js';

export async function getVaultUnlock(req: Request, res: Response) {
  if (!req.auth) {
    res.status(401).json({
      error: {
        code: 'AUTHENTICATION_REQUIRED',

        message: 'Authentication is required.',
      },
    });

    return;
  }

  try {
    const result = await getVaultUnlockMaterial(req.auth.userId);

    res.status(200).json(result);
  } catch (error) {
    handleCryptoMaterialError(error, res);
  }
}

export async function getMasterPasswordRecovery(req: Request, res: Response) {
  if (!req.auth) {
    res.status(401).json({
      error: {
        code: 'AUTHENTICATION_REQUIRED',

        message: 'Authentication is required.',
      },
    });

    return;
  }

  try {
    const result = await getMasterPasswordRecoveryMaterial(req.auth.userId);

    res.status(200).json(result);
  } catch (error) {
    handleCryptoMaterialError(error, res);
  }
}

function handleCryptoMaterialError(error: unknown, res: Response) {
  if (error instanceof Error && error.message === 'CRYPTO_PROTOCOL_UNSUPPORTED') {
    res.status(409).json({
      error: {
        code: 'CRYPTO_PROTOCOL_UNSUPPORTED',

        message: 'This account uses an unsupported cryptographic protocol.',
      },
    });

    return;
  }

  if (error instanceof Error && error.message === 'CRYPTO_STATE_INVALID') {
    res.status(409).json({
      error: {
        code: 'CRYPTO_STATE_INVALID',

        message: 'The account cryptographic state is incomplete.',
      },
    });

    return;
  }

  throw error;
}

export async function completeMasterPasswordRecoveryRequest(req: Request, res: Response) {
  if (!req.auth) {
    res.status(401).json({
      error: {
        code: 'AUTHENTICATION_REQUIRED',

        message: 'Authentication is required.',
      },
    });

    return;
  }

  const result = completeMasterPasswordRecoverySchema.safeParse(req.body);

  if (!result.success) {
    res.status(400).json({
      error: {
        code: 'VALIDATION_ERROR',

        message: 'Invalid Master Password recovery payload.',
      },
    });

    return;
  }

  try {
    await completeMasterPasswordRecovery(req.auth.userId, result.data);

    /*
     * All sessions were revoked atomically.
     * Remove the opaque token from this browser
     * as well.
     */
    res.clearCookie(sessionCookieName(), sessionCookieClearOptions());

    res.status(204).end();
  } catch (error) {
    if (error instanceof Error && error.message === 'INVALID_CRYPTO_MATERIAL') {
      res.status(400).json({
        error: {
          code: 'INVALID_CRYPTO_MATERIAL',

          message: 'Invalid encrypted recovery material.',
        },
      });

      return;
    }

    if (error instanceof Error && error.message === 'RECOVERY_CONFLICT') {
      res.status(409).json({
        error: {
          code: 'RECOVERY_CONFLICT',

          message: 'The account cryptographic state changed during recovery.',
        },
      });

      return;
    }

    if (error instanceof Error && error.message === 'CRYPTO_PROTOCOL_UNSUPPORTED') {
      res.status(409).json({
        error: {
          code: 'CRYPTO_PROTOCOL_UNSUPPORTED',

          message: 'This account uses an unsupported cryptographic protocol.',
        },
      });

      return;
    }

    if (error instanceof Error && error.message === 'CRYPTO_STATE_INVALID') {
      res.status(409).json({
        error: {
          code: 'CRYPTO_STATE_INVALID',

          message: 'The account cryptographic state is incomplete.',
        },
      });

      return;
    }

    throw error;
  }
}
