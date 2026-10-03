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

  useEffect(() => {
    const dialog = dialogRef.current;

    if (!dialog) {
      return;
    }

    if (open && !dialog.open) {
      dialog.showModal();
      cancelButtonRef.current?.focus();
      return;
    }

    if (!open && dialog.open) {
      dialog.close();
    }
  }, [open]);

  return (
    <dialog
      ref={dialogRef}
      className="confirmation-dialog"
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
          <h2>{title}</h2>
          <p>{description}</p>
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
