import type { ReactNode } from 'react';

interface AppShellProps {
  children: ReactNode;
  email: string;
  vaultStatus: 'locked' | 'unlocked';
  vaultActive: boolean;
  securityActive: boolean;
  onNavigateVault: () => void;
  onNavigateSecurity: () => void;
  onLockVault?: () => void;
  onSignOut: () => void;
}

export function AppShell({
  children,
  email,
  vaultStatus,
  vaultActive,
  securityActive,
  onNavigateVault,
  onNavigateSecurity,
  onLockVault,
  onSignOut,
}: AppShellProps) {
  const unlocked = vaultStatus === 'unlocked';

  return (
    <div className="workspace">
      <aside className="workspace-sidebar">
        <div className="workspace-brand">
          <div className="app-brand__mark" aria-hidden="true">
            R
          </div>

          <strong>Rory</strong>
        </div>

        <nav className="workspace-nav" aria-label="Main navigation">
          <button
            className={`workspace-nav__item ${vaultActive ? 'workspace-nav__item--active' : ''}`}
            type="button"
            onClick={onNavigateVault}
          >
            <span aria-hidden="true">▣</span>
            Vault
          </button>

          <button
            className={`workspace-nav__item ${securityActive ? 'workspace-nav__item--active' : ''}`}
            type="button"
            onClick={onNavigateSecurity}
          >
            <span aria-hidden="true">◇</span>
            Security
          </button>
        </nav>

        <div className="workspace-sidebar__footer">
          <div className={`vault-status vault-status--${vaultStatus}`}>
            <span className="vault-status__indicator" />

            <div>
              <strong>Vault {vaultStatus}</strong>
              <span>{unlocked ? 'Keys available locally' : 'Keys not loaded'}</span>
            </div>
          </div>

          {unlocked && onLockVault && (
            <button className="workspace-sidebar__action" type="button" onClick={onLockVault}>
              Lock vault
            </button>
          )}

          <button className="workspace-sidebar__action" type="button" onClick={onSignOut}>
            Sign out
          </button>
        </div>
      </aside>

      <div className="workspace-main">
        <header className="workspace-topbar">
          <div className="workspace-topbar__status">
            <span
              className={`workspace-topbar__dot ${
                unlocked ? 'workspace-topbar__dot--unlocked' : ''
              }`}
            />

            {unlocked ? 'Vault unlocked' : 'Vault locked'}
          </div>

          <div className="workspace-user" title={email}>
            {email}
          </div>
        </header>

        <div className="workspace-content">{children}</div>
      </div>
    </div>
  );
}
