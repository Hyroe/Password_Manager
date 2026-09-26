import type { Request, Response } from 'express';

import { decodeCanonicalBase64UrlValue } from '../../lib/base64Url.js';

import {
  encryptedVaultItemRevisionSchema,
  encryptedVaultItemSchema,
  vaultIdParamsSchema,
  vaultItemDeleteSchema,
  vaultItemParamsSchema,
  vaultItemUpdateOptionsSchema,
  vaultItemRestoreSchema,
  vaultItemListQuerySchema,
} from './vaultItemSchemas.js';

import {
  createEncryptedVaultItem,
  createEncryptedVaultItemRevision,
  getEncryptedVaultItem,
  getVaultItemUpdateOptions,
  listEncryptedVaultItemsPage,
  reserveVaultItem,
  softDeleteVaultItem,
  restoreVaultItem,
} from './vaultItemService.js';

import { decodeVaultItemCursor } from './vaultItemPagination.js';

function handleVaultItemError(error: unknown, res: Response): boolean {
  if (!(error instanceof Error)) {
    return false;
  }

  switch (error.message) {
    case 'VAULT_NOT_FOUND':
      res.status(404).json({
        error: {
          code: 'VAULT_NOT_FOUND',
          message: 'Vault not found.',
        },
      });

      return true;

    case 'ITEM_RESERVATION_NOT_FOUND':
      res.status(404).json({
        error: {
          code: 'ITEM_RESERVATION_NOT_FOUND',

          message: 'Item reservation not found.',
        },
      });

      return true;

    case 'ITEM_NOT_FOUND':
      res.status(404).json({
        error: {
          code: 'ITEM_NOT_FOUND',
          message: 'Item not found.',
        },
      });

      return true;

    case 'ITEM_REVISION_CONFLICT':
      res.status(409).json({
        error: {
          code: 'ITEM_REVISION_CONFLICT',

          message: 'The item revision is stale or has already been used.',
        },
      });

      return true;

    case 'VAULT_KEY_VERSION_CHANGED':
      res.status(409).json({
        error: {
          code: 'VAULT_KEY_VERSION_CHANGED',

          message: 'The vault key changed. Reserve the item again.',
        },
      });

      return true;

    case 'CRYPTO_STATE_INVALID':
      res.status(409).json({
        error: {
          code: 'CRYPTO_STATE_INVALID',

          message: 'The vault cryptographic state is incomplete.',
        },
      });

      return true;

    case 'INVALID_CRYPTO_MATERIAL':
    case 'INVALID_BASE64URL':
      res.status(400).json({
        error: {
          code: 'INVALID_CRYPTO_MATERIAL',

          message: 'Invalid encrypted item material.',
        },
      });

      return true;

    default:
      return false;
  }
}

export async function reserveVaultItemController(req: Request, res: Response) {
  if (!req.auth) {
    res.status(401).json({
      error: {
        code: 'AUTHENTICATION_REQUIRED',

        message: 'Authentication is required.',
      },
    });

    return;
  }

  const parsed = vaultIdParamsSchema.safeParse(req.params);

  if (!parsed.success) {
    res.status(400).json({
      error: {
        code: 'INVALID_REQUEST',
        message: 'Invalid vault ID.',
      },
    });

    return;
  }

  try {
    const result = await reserveVaultItem(req.auth.userId, parsed.data.vaultId);

    res.status(201).json(result);
  } catch (error) {
    if (handleVaultItemError(error, res)) {
      return;
    }

    throw error;
  }
}

export async function createVaultItemController(req: Request, res: Response) {
  if (!req.auth) {
    res.status(401).json({
      error: {
        code: 'AUTHENTICATION_REQUIRED',

        message: 'Authentication is required.',
      },
    });

    return;
  }

  const params = vaultIdParamsSchema.safeParse(req.params);

  const body = encryptedVaultItemSchema.safeParse(req.body);

  if (!params.success || !body.success) {
    res.status(400).json({
      error: {
        code: 'INVALID_REQUEST',

        message: 'Invalid encrypted item request.',
      },
    });

    return;
  }

  try {
    const itemKeyEnvelope = decodeCanonicalBase64UrlValue(body.data.itemKeyEnvelope);

    const ciphertext = decodeCanonicalBase64UrlValue(body.data.ciphertext);

    const result = await createEncryptedVaultItem(req.auth.userId, params.data.vaultId, {
      itemId: body.data.itemId,

      revisionNumber: body.data.revisionNumber,

      payloadVersion: body.data.payloadVersion,

      ciphertextVersion: body.data.ciphertextVersion,

      itemKeyVersion: body.data.itemKeyVersion,

      vaultKeyVersion: body.data.vaultKeyVersion,

      envelopeVersion: body.data.envelopeVersion,

      itemKeyEnvelope,
      ciphertext,
    });

    res.status(201).json(result);
  } catch (error) {
    if (handleVaultItemError(error, res)) {
      return;
    }

    throw error;
  }
}

export async function listVaultItemsController(req: Request, res: Response) {
  if (!req.auth) {
    res.status(401).json({
      error: {
        code: 'AUTHENTICATION_REQUIRED',

        message: 'Authentication is required.',
      },
    });

    return;
  }

  const params = vaultIdParamsSchema.safeParse(req.params);

  const query = vaultItemListQuerySchema.safeParse(req.query);

  if (!params.success || !query.success) {
    res.status(400).json({
      error: {
        code: 'INVALID_REQUEST',

        message: 'Invalid vault item list request.',
      },
    });

    return;
  }

  const includeDeleted = query.data.includeDeleted === 'true';

  try {
    const cursor = query.data.cursor ? decodeVaultItemCursor(query.data.cursor) : undefined;

    if (
      cursor &&
      (cursor.vaultId !== params.data.vaultId || cursor.includeDeleted !== includeDeleted)
    ) {
      res.status(400).json({
        error: {
          code: 'INVALID_PAGINATION_CURSOR',

          message: 'Pagination cursor does not match this request.',
        },
      });

      return;
    }

    const result = await listEncryptedVaultItemsPage(req.auth.userId, params.data.vaultId, {
      includeDeleted,
      limit: query.data.limit,
      ...(cursor ? { cursor } : {}),
    });

    res.status(200).json(result);
  } catch (error) {
    if (error instanceof Error && error.message === 'INVALID_PAGINATION_CURSOR') {
      res.status(400).json({
        error: {
          code: 'INVALID_PAGINATION_CURSOR',

          message: 'Invalid pagination cursor.',
        },
      });

      return;
    }

    if (handleVaultItemError(error, res)) {
      return;
    }

    throw error;
  }
}

export async function getVaultItemController(req: Request, res: Response) {
  if (!req.auth) {
    res.status(401).json({
      error: {
        code: 'AUTHENTICATION_REQUIRED',

        message: 'Authentication is required.',
      },
    });

    return;
  }

  const parsed = vaultItemParamsSchema.safeParse(req.params);

  if (!parsed.success) {
    res.status(400).json({
      error: {
        code: 'INVALID_REQUEST',

        message: 'Invalid vault or item ID.',
      },
    });

    return;
  }

  try {
    const item = await getEncryptedVaultItem(
      req.auth.userId,
      parsed.data.vaultId,
      parsed.data.itemId,
    );

    res.status(200).json(item);
  } catch (error) {
    if (handleVaultItemError(error, res)) {
      return;
    }

    throw error;
  }
}

export async function getVaultItemUpdateOptionsController(req: Request, res: Response) {
  if (!req.auth) {
    res.status(401).json({
      error: {
        code: 'AUTHENTICATION_REQUIRED',

        message: 'Authentication is required.',
      },
    });

    return;
  }

  const params = vaultItemParamsSchema.safeParse(req.params);

  const body = vaultItemUpdateOptionsSchema.safeParse(req.body);

  if (!params.success || !body.success) {
    res.status(400).json({
      error: {
        code: 'INVALID_REQUEST',

        message: 'Invalid item revision request.',
      },
    });

    return;
  }

  try {
    const result = await getVaultItemUpdateOptions(
      req.auth.userId,
      params.data.vaultId,
      params.data.itemId,
      body.data.expectedRevisionNumber,
    );

    res.status(200).json(result);
  } catch (error) {
    if (handleVaultItemError(error, res)) {
      return;
    }

    throw error;
  }
}

export async function createVaultItemRevisionController(req: Request, res: Response) {
  if (!req.auth) {
    res.status(401).json({
      error: {
        code: 'AUTHENTICATION_REQUIRED',

        message: 'Authentication is required.',
      },
    });

    return;
  }

  const params = vaultItemParamsSchema.safeParse(req.params);

  const body = encryptedVaultItemRevisionSchema.safeParse(req.body);

  if (!params.success || !body.success) {
    res.status(400).json({
      error: {
        code: 'INVALID_REQUEST',

        message: 'Invalid encrypted revision request.',
      },
    });

    return;
  }

  try {
    const itemKeyEnvelope = decodeCanonicalBase64UrlValue(body.data.itemKeyEnvelope);

    const ciphertext = decodeCanonicalBase64UrlValue(body.data.ciphertext);

    const result = await createEncryptedVaultItemRevision(
      req.auth.userId,
      params.data.vaultId,
      params.data.itemId,
      {
        expectedRevisionNumber: body.data.expectedRevisionNumber,

        revisionNumber: body.data.revisionNumber,

        payloadVersion: body.data.payloadVersion,

        ciphertextVersion: body.data.ciphertextVersion,

        itemKeyVersion: body.data.itemKeyVersion,

        vaultKeyVersion: body.data.vaultKeyVersion,

        envelopeVersion: body.data.envelopeVersion,

        itemKeyEnvelope,
        ciphertext,
      },
    );

    res.status(201).json(result);
  } catch (error) {
    if (handleVaultItemError(error, res)) {
      return;
    }

    throw error;
  }
}

export async function deleteVaultItemController(req: Request, res: Response) {
  if (!req.auth) {
    res.status(401).json({
      error: {
        code: 'AUTHENTICATION_REQUIRED',

        message: 'Authentication is required.',
      },
    });

    return;
  }

  const params = vaultItemParamsSchema.safeParse(req.params);

  const body = vaultItemDeleteSchema.safeParse(req.body);

  if (!params.success || !body.success) {
    res.status(400).json({
      error: {
        code: 'INVALID_REQUEST',

        message: 'Invalid vault item delete request.',
      },
    });

    return;
  }

  try {
    const result = await softDeleteVaultItem(
      req.auth.userId,
      params.data.vaultId,
      params.data.itemId,
      body.data.expectedRevisionNumber,
    );

    res.status(200).json(result);
  } catch (error) {
    if (handleVaultItemError(error, res)) {
      return;
    }

    throw error;
  }
}

export async function restoreVaultItemController(req: Request, res: Response) {
  if (!req.auth) {
    res.status(401).json({
      error: {
        code: 'AUTHENTICATION_REQUIRED',

        message: 'Authentication is required.',
      },
    });

    return;
  }

  const params = vaultItemParamsSchema.safeParse(req.params);

  const body = vaultItemRestoreSchema.safeParse(req.body);

  if (!params.success || !body.success) {
    res.status(400).json({
      error: {
        code: 'INVALID_REQUEST',

        message: 'Invalid vault item restore request.',
      },
    });

    return;
  }

  try {
    const result = await restoreVaultItem(
      req.auth.userId,
      params.data.vaultId,
      params.data.itemId,
      body.data.expectedRevisionNumber,
    );

    res.status(200).json(result);
  } catch (error) {
    if (handleVaultItemError(error, res)) {
      return;
    }

    throw error;
  }
}
