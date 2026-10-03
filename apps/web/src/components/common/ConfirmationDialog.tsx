import { useEffect, useRef } from 'react';

interface ConfirmationDialogProps {
  open: boolean;
  title: string;
  description: string;
  confirmLabel: string;
  busy?: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}

const titleId = 'confirmation-dialog-title';
const descriptionId = 'confirmation-dialog-description';

export function ConfirmationDialog({
  open,
  title,
  description,
  confirmLabel,
  busy = false,
  onCancel,
  onConfirm,
}: ConfirmationDialogProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const cancelButtonRef = useRef<HTMLButtonElement>(null);
  const previouslyFocusedElementRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    const dialog = dialogRef.current;

    if (!dialog) {
      return;
    }

    if (open && !dialog.open) {
      previouslyFocusedElementRef.current =
        document.activeElement instanceof HTMLElement ? document.activeElement : null;

      dialog.showModal();
      cancelButtonRef.current?.focus();

      return;
    }

    if (!open && dialog.open) {
      dialog.close();

      const previouslyFocusedElement = previouslyFocusedElementRef.current;

      previouslyFocusedElementRef.current = null;

      if (previouslyFocusedElement?.isConnected) {
        previouslyFocusedElement.focus();
      }
    }
  }, [open]);

  return (
    <dialog
      ref={dialogRef}
      className="confirmation-dialog"
      aria-labelledby={titleId}
      aria-describedby={descriptionId}
      aria-busy={busy}
      onCancel={(event) => {
        event.preventDefault();

        if (!busy) {
          onCancel();
        }
      }}
    >
      <div className="confirmation-dialog__body">
        <div className="confirmation-dialog__icon" aria-hidden="true">
          !
        </div>

        <div className="confirmation-dialog__content">
          <h2 id={titleId}>{title}</h2>

          <p id={descriptionId}>{description}</p>
        </div>
      </div>

      <footer className="confirmation-dialog__actions">
        <button
          ref={cancelButtonRef}
          className="button-secondary"
          type="button"
          disabled={busy}
          onClick={onCancel}
        >
          Cancel
        </button>

        <button className="button-danger" type="button" disabled={busy} onClick={onConfirm}>
          {busy ? 'Working…' : confirmLabel}
        </button>
      </footer>
    </dialog>
  );
}
