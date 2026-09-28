import { matchPath } from 'react-router-dom';

import { routes } from './routes';

export type RuntimeState =
  'CHECKING_SESSION' | 'SESSION_UNAVAILABLE' | 'SIGNED_OUT' | 'AUTHENTICATED_LOCKED' | 'UNLOCKED';

function isSignedOutPath(pathname: string): boolean {
  return pathname === routes.login || pathname === routes.register;
}

function isLockedPath(pathname: string): boolean {
  return pathname === routes.vault || pathname === routes.security || pathname === routes.recovery;
}

function isUnlockedPath(pathname: string): boolean {
  if (pathname === routes.vault || pathname === routes.security) {
    return true;
  }

  return (
    matchPath(
      {
        path: routes.vaultItemPattern,
        end: true,
      },
      pathname,
    ) !== null
  );
}

export function resolveRuntimeRedirect(
  runtimeState: RuntimeState,
  pathname: string,
): string | null {
  switch (runtimeState) {
    case 'CHECKING_SESSION':
    case 'SESSION_UNAVAILABLE':
      return null;

    case 'SIGNED_OUT':
      return isSignedOutPath(pathname) ? null : routes.login;

    case 'AUTHENTICATED_LOCKED':
      return isLockedPath(pathname) ? null : routes.vault;

    case 'UNLOCKED':
      return isUnlockedPath(pathname) ? null : routes.vault;
  }
}
