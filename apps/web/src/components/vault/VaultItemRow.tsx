import type { VaultSearchEntry } from '../../lib/vaultSearch';

interface VaultItemRowProps {
  entry: VaultSearchEntry;
  disabled: boolean;
  onOpen: (itemId: string) => void;
  onDelete: (itemId: string) => void;
}

export function VaultItemRow({ entry, disabled, onOpen, onDelete }: VaultItemRowProps) {
  const monogram = entry.name.trim().charAt(0).toUpperCase() || '?';

  return (
    <article className="vault-item-row">
      <button
        className="vault-item-row__content"
        type="button"
        disabled={disabled}
        onClick={() => {
          onOpen(entry.itemId);
        }}
      >
        <span className="vault-item-row__icon" aria-hidden="true">
          {monogram}
        </span>

        <span className="vault-item-row__details">
          <strong>{entry.name}</strong>

          {entry.username && <span>{entry.username}</span>}

          {entry.urls[0] && <span className="vault-item-row__url">{entry.urls[0]}</span>}
        </span>

        <span className="vault-item-row__chevron" aria-hidden="true">
          ›
        </span>
      </button>

      <button
        className="vault-item-row__delete"
        type="button"
        disabled={disabled}
        aria-label={`Delete ${entry.name}`}
        onClick={() => {
          onDelete(entry.itemId);
        }}
      >
        Delete
      </button>
    </article>
  );
}
