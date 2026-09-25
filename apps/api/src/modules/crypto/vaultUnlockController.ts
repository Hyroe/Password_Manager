import type { Request, Response } from 'express';

import { getVaultUnlockMaterial } from './vaultUnlockService.js';

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
