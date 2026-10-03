interface AppNotificationsProps {
  message: string;
  error: string;
  webAuthnSupported: boolean;
  onDismissMessage: () => void;
  onDismissError: () => void;
}

export function AppNotifications({
  message,
  error,
  webAuthnSupported,
  onDismissMessage,
  onDismissError,
}: AppNotificationsProps) {
  if (webAuthnSupported && !message && !error) {
    return null;
  }

  return (
    <div className="notification-region" aria-label="Notifications">
      {!webAuthnSupported && (
        <div className="app-notification app-notification--warning" role="alert" aria-atomic="true">
          <span className="app-notification__icon" aria-hidden="true">
            !
          </span>

          <div className="app-notification__content">
            <strong>Passkeys unavailable</strong>
            <span>This browser does not support WebAuthn.</span>
          </div>
        </div>
      )}

      {message && (
        <div
          className="app-notification app-notification--success"
          role="status"
          aria-atomic="true"
        >
          <span className="app-notification__icon" aria-hidden="true">
            ✓
          </span>

          <div className="app-notification__content">
            <strong>Done</strong>
            <span>{message}</span>
          </div>

          <button
            className="app-notification__close"
            type="button"
            aria-label="Dismiss success notification"
            onClick={onDismissMessage}
          >
            ×
          </button>
        </div>
      )}

      {error && (
        <div className="app-notification app-notification--error" role="alert" aria-atomic="true">
          <span className="app-notification__icon" aria-hidden="true">
            !
          </span>

          <div className="app-notification__content">
            <strong>Something needs attention</strong>
            <span>{error}</span>
          </div>

          <button
            className="app-notification__close"
            type="button"
            aria-label="Dismiss error notification"
            onClick={onDismissError}
          >
            ×
          </button>
        </div>
      )}
    </div>
  );
}
