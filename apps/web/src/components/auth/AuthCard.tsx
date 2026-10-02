import type { ReactNode } from 'react';

interface AuthCardProps {
  title: string;
  description?: string;
  children: ReactNode;
}

export function AuthCard({ title, description, children }: AuthCardProps) {
  return (
    <section className="auth-card">
      <header className="auth-card__header">
        <h2>{title}</h2>

        {description && <p>{description}</p>}
      </header>

      <div className="auth-card__body">{children}</div>
    </section>
  );
}
