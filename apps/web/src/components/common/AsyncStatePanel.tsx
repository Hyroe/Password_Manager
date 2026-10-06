import type { ReactNode } from 'react';

interface AsyncStatePanelProps {
  variant: 'loading' | 'error' | 'empty';
  title: string;
  description?: string;
  action?: ReactNode;
  compact?: boolean;
}

export function AsyncStatePanel({
  variant,
  title,
  description,
  action,
  compact = false,
}: AsyncStatePanelProps) {
  return (
    <div
      className={`async-state async-state--${variant} ${compact ? 'async-state--compact' : ''}`}
      role={variant === 'error' ? 'alert' : 'status'}
      aria-live={variant === 'error' ? 'assertive' : 'polite'}
    >
      <div className="async-state__icon" aria-hidden="true">
        {variant === 'loading' ? '…' : variant === 'error' ? '!' : '◇'}
      </div>

      <div className="async-state__content">
        <strong>{title}</strong>

        {description && <p>{description}</p>}
      </div>

      {action && <div className="async-state__action">{action}</div>}
    </div>
  );
}
