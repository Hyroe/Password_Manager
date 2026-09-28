import { matchPath } from 'react-router-dom';

import { routes } from './routes';

export function getVaultItemIdFromPath(pathname: string): string | null {
  const match = matchPath(
    {
      path: routes.vaultItemPattern,
      end: true,
    },
    pathname,
  );

  return match?.params.itemId ?? null;
}
