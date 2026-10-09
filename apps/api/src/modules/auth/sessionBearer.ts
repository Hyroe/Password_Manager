import type { Request } from 'express';

export type BearerSessionTokenResult =
  | {
      kind: 'ABSENT';
    }
  | {
      kind: 'INVALID';
    }
  | {
      kind: 'TOKEN';
      token: string;
    };

export function getBearerSessionTokenFromRequest(req: Request): BearerSessionTokenResult {
  const authorization = req.get('authorization');

  if (!authorization) {
    return {
      kind: 'ABSENT',
    };
  }

  const match = /^Bearer[ \t]+([^ \t]+)$/i.exec(authorization.trim());

  if (!match) {
    return {
      kind: 'INVALID',
    };
  }

  const token = match[1];

  if (!token) {
    return {
      kind: 'INVALID',
    };
  }

  return {
    kind: 'TOKEN',
    token,
  };
}
