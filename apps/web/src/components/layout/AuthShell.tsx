import type { ReactNode } from 'react';

interface AuthShellProps {
  children: ReactNode;
}

export function AuthShell({ children }: AuthShellProps) {
  return (
    <div className="auth-shell">
      <header className="auth-shell__brand">
        <div className="app-brand__mark" aria-hidden="true">
          R
        </div>

        <div>
          <h1>Rory</h1>
          <p>Private vault</p>
        </div>
      </header>

      <div className="auth-shell__content">{children}</div>

      <footer className="auth-shell__footer">Encrypted locally. Private by design.</footer>
    </div>
  );
}
