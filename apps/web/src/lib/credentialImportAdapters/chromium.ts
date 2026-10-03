import type {
  CredentialImportAdapter,
  CredentialImportRow,
  CredentialImportRowResult,
} from '../credentialImport';

const USERNAME_HEADERS = ['username', 'login'] as const;

const NAME_HEADERS = ['name', 'title'] as const;

const NOTE_HEADERS = ['note', 'notes', 'comment', 'comments'] as const;

function firstValue(row: CredentialImportRow, headers: readonly string[]): string {
  for (const header of headers) {
    const value = row.get(header);

    if (value !== undefined) {
      return value;
    }
  }

  return '';
}

function deriveName(url: string): string {
  try {
    const parsed = new URL(url);

    const hostname = parsed.hostname.replace(/^www\./i, '');

    if (hostname) {
      return hostname;
    }
  } catch {
    // Preserve importability even when the exported URL is unusual.
  }

  return url || 'Imported login';
}

export const chromiumCredentialImportAdapter: CredentialImportAdapter = {
  id: 'CHROMIUM_CSV',

  label: 'Chromium-compatible CSV',

  canParse(headers) {
    const hasUsernameHeader = USERNAME_HEADERS.some((header) => headers.includes(header));

    return headers.includes('url') && headers.includes('password') && hasUsernameHeader;
  },

  mapRow(row): CredentialImportRowResult {
    const url = row.get('url')?.trim() ?? '';

    /*
     * Password is intentionally not trimmed.
     * Whitespace may be part of the actual credential.
     */
    const password = row.get('password') ?? '';

    const username = firstValue(row, USERNAME_HEADERS);

    const explicitName = firstValue(row, NAME_HEADERS).trim();

    const notes = firstValue(row, NOTE_HEADERS);

    if (!url || password.length === 0) {
      return {
        ok: false,
        issue: 'MISSING_REQUIRED_FIELD',
      };
    }

    return {
      ok: true,

      draft: {
        name: explicitName || deriveName(url),
        username,
        password,
        urls: [url],
        notes,
      },
    };
  },
};
