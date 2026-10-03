import * as Papa from 'papaparse';

import type { LoginItemDraft } from './cryptoCore';

export const MAX_IMPORT_ROWS = 10_000;
export const MAX_IMPORT_FIELD_LENGTH = 131_072;
export const MAX_IMPORT_HEADERS = 100;

export type CredentialImportErrorCode =
  | 'EMPTY_FILE'
  | 'INVALID_CSV'
  | 'UNSUPPORTED_FORMAT'
  | 'DUPLICATE_HEADER'
  | 'TOO_MANY_HEADERS'
  | 'TOO_MANY_ROWS'
  | 'FILE_TOO_LARGE'
  | 'FILE_READ_FAILED';

export type CredentialImportRowIssue = 'INVALID_ROW' | 'MISSING_REQUIRED_FIELD' | 'FIELD_TOO_LARGE';

export class CredentialImportError extends Error {
  readonly code: CredentialImportErrorCode;

  constructor(code: CredentialImportErrorCode, message: string) {
    super(message);

    this.name = 'CredentialImportError';
    this.code = code;
  }
}

export type CredentialImportRow = ReadonlyMap<string, string>;

export type CredentialImportRowResult =
  | {
      ok: true;
      draft: LoginItemDraft;
    }
  | {
      ok: false;
      issue: CredentialImportRowIssue;
    };

export interface CredentialImportAdapter {
  id: string;
  label: string;

  /**
   * Headers are trimmed, lower-cased, and have the UTF-8 BOM
   * removed from the first column before this method is called.
   */
  canParse(headers: readonly string[]): boolean;

  mapRow(row: CredentialImportRow, rowNumber: number): CredentialImportRowResult;
}

export interface AcceptedCredentialImportRow {
  rowNumber: number;
  draft: LoginItemDraft;
}

export interface RejectedCredentialImportRow {
  rowNumber: number;
  issue: CredentialImportRowIssue;
}

export interface CredentialImportResult {
  adapterId: string;
  adapterLabel: string;

  totalRows: number;

  accepted: AcceptedCredentialImportRow[];
  rejected: RejectedCredentialImportRow[];
}

function normalizeHeader(value: string, index: number): string {
  const withoutBom = index === 0 ? value.replace(/^\uFEFF/, '') : value;

  return withoutBom.trim().toLowerCase();
}

function parseRows(csv: string): string[][] {
  const result = Papa.parse<string[]>(csv, {
    skipEmptyLines: 'greedy',
    dynamicTyping: false,
  });

  if (result.errors.length > 0) {
    throw new CredentialImportError('INVALID_CSV', 'The selected file is not a valid CSV.');
  }

  return result.data;
}

function validateHeaders(rawHeaders: string[]): string[] {
  const headers = rawHeaders.map(normalizeHeader);

  if (headers.length > MAX_IMPORT_HEADERS) {
    throw new CredentialImportError(
      'TOO_MANY_HEADERS',
      `A maximum of ${MAX_IMPORT_HEADERS} columns is supported.`,
    );
  }

  if (headers.length === 0 || headers.every((header) => header.length === 0)) {
    throw new CredentialImportError('EMPTY_FILE', 'The selected CSV does not contain headers.');
  }

  const nonEmptyHeaders = headers.filter((header) => header.length > 0);

  if (nonEmptyHeaders.length !== headers.length) {
    throw new CredentialImportError('INVALID_CSV', 'The selected CSV contains an invalid header.');
  }

  if (new Set(headers).size !== headers.length) {
    throw new CredentialImportError(
      'DUPLICATE_HEADER',
      'The selected CSV contains duplicate headers.',
    );
  }

  return headers;
}

function createRow(headers: readonly string[], values: readonly string[]): CredentialImportRow {
  const row = new Map<string, string>();

  headers.forEach((header, index) => {
    row.set(header, values[index] ?? '');
  });

  return row;
}

function rowContainsOversizedField(values: readonly string[]): boolean {
  return values.some((value) => value.length > MAX_IMPORT_FIELD_LENGTH);
}

export function parseCredentialCsv(
  csv: string,
  adapters: readonly CredentialImportAdapter[],
): CredentialImportResult {
  if (csv.trim().length === 0) {
    throw new CredentialImportError('EMPTY_FILE', 'The selected CSV is empty.');
  }

  const rows = parseRows(csv);

  if (rows.length === 0) {
    throw new CredentialImportError('EMPTY_FILE', 'The selected CSV is empty.');
  }

  const [rawHeaders, ...dataRows] = rows;

  if (!rawHeaders) {
    throw new CredentialImportError('EMPTY_FILE', 'The selected CSV is empty.');
  }

  const headers = validateHeaders(rawHeaders);

  if (dataRows.length > MAX_IMPORT_ROWS) {
    throw new CredentialImportError(
      'TOO_MANY_ROWS',
      `A maximum of ${MAX_IMPORT_ROWS} credentials can be imported at once.`,
    );
  }

  const adapter = adapters.find((candidate) => candidate.canParse(headers));

  if (!adapter) {
    throw new CredentialImportError(
      'UNSUPPORTED_FORMAT',
      'The selected CSV format is not supported.',
    );
  }

  const accepted: AcceptedCredentialImportRow[] = [];
  const rejected: RejectedCredentialImportRow[] = [];

  dataRows.forEach((values, index) => {
    /*
     * Row numbers are reported using their physical CSV position:
     *
     * row 1 = headers
     * row 2 = first credential
     */
    const rowNumber = index + 2;

    if (values.length > headers.length) {
      rejected.push({
        rowNumber,
        issue: 'INVALID_ROW',
      });

      return;
    }

    if (rowContainsOversizedField(values)) {
      rejected.push({
        rowNumber,
        issue: 'FIELD_TOO_LARGE',
      });

      return;
    }

    const row = createRow(headers, values);

    try {
      const mapped = adapter.mapRow(row, rowNumber);

      if (!mapped.ok) {
        rejected.push({
          rowNumber,
          issue: mapped.issue,
        });

        return;
      }

      accepted.push({
        rowNumber,
        draft: mapped.draft,
      });
    } catch {
      /*
       * Adapter exceptions are intentionally collapsed into a safe
       * row-level result. Never propagate imported field contents
       * through an error message.
       */
      rejected.push({
        rowNumber,
        issue: 'INVALID_ROW',
      });
    }
  });

  return {
    adapterId: adapter.id,
    adapterLabel: adapter.label,

    totalRows: dataRows.length,

    accepted,
    rejected,
  };
}
