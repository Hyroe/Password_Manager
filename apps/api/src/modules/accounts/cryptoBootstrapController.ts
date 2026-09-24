import type { Request, Response } from 'express';

import { cryptoBootstrapOptionsSchema } from './cryptoBootstrapSchemas.js';
import { completeCryptoBootstrapSchema } from './cryptoBootstrapSchemas.js';

import { completeCryptoBootstrap, createCryptoBootstrapOptions } from './cryptoBootstrapService.js';

export async function cryptoBootstrapOptions(req: Request, res: Response) {
  const result = cryptoBootstrapOptionsSchema.safeParse(req.body);

  if (!result.success) {
    res.status(400).json({
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Invalid crypto bootstrap request.',
      },
    });

    return;
  }

  try {
    const options = await createCryptoBootstrapOptions(
      result.data.registrationId,
      result.data.bootstrapToken,
    );

    res.status(200).json(options);
  } catch (error) {
    if (error instanceof Error && error.message === 'INVALID_BOOTSTRAP') {
      res.status(400).json({
        error: {
          code: 'BOOTSTRAP_INVALID',
          message: 'The account bootstrap request is invalid or expired.',
        },
      });

      return;
    }

    throw error;
  }
}

export async function cryptoBootstrapComplete(req: Request, res: Response) {
  const result = completeCryptoBootstrapSchema.safeParse(req.body);

  if (!result.success) {
    res.status(400).json({
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Invalid crypto bootstrap payload.',
      },
    });

    return;
  }

  try {
    const completion = await completeCryptoBootstrap(result.data);

    res.status(completion.alreadyCompleted ? 200 : 201).json({
      userId: completion.userId,
      vaultId: completion.vaultId,
      status: completion.status,
    });
  } catch (error) {
    if (
      error instanceof Error &&
      (error.message === 'INVALID_BOOTSTRAP' || error.message === 'INVALID_CRYPTO_MATERIAL')
    ) {
      res.status(400).json({
        error: {
          code: 'BOOTSTRAP_INVALID',
          message: 'The account bootstrap request is invalid or expired.',
        },
      });

      return;
    }

    if (error instanceof Error && error.message === 'ACCOUNT_ALREADY_EXISTS') {
      res.status(409).json({
        error: {
          code: 'ACCOUNT_ALREADY_EXISTS',
          message: 'An account already exists for this identity.',
        },
      });

      return;
    }

    throw error;
  }
}
