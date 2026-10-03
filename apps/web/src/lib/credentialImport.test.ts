import { describe, expect, it } from 'vitest';

import {
  CredentialImportError,
  MAX_IMPORT_FIELD_LENGTH,
  MAX_IMPORT_ROWS,
  parseCredentialCsv,
  type CredentialImportAdapter,
} from './credentialImport';

const testAdapter: CredentialImportAdapter = {
  id: 'TEST',
  label: 'Test CSV',

  canParse(headers) {
    return (
      headers.includes('name') &&
      headers.includes('username') &&
      headers.includes('password') &&
      headers.includes('url') &&
      headers.includes('notes')
    );
  },

  mapRow(row) {
    const name = row.get('name')?.trim() ?? '';

    if (!name) {
      return {
        ok: false,
        issue: 'MISSING_REQUIRED_FIELD',
      };
    }

    const url = row.get('url')?.trim() ?? '';

    return {
      ok: true,

      draft: {
        name,
        username: row.get('username') ?? '',
        password: row.get('password') ?? '',
        urls: url ? [url] : [],
        notes: row.get('notes') ?? '',
      },
    };
  },
};

describe('parseCredentialCsv', () => {
  it('parses supported credentials into LoginItemDraft values', () => {
    const result = parseCredentialCsv(
      [
        'name,username,password,url,notes',
        'GitHub,user@example.com,secret123,https://github.com,Personal',
      ].join('\n'),
      [testAdapter],
    );

    expect(result).toEqual({
      adapterId: 'TEST',
      adapterLabel: 'Test CSV',
      totalRows: 1,

      accepted: [
        {
          rowNumber: 2,

          draft: {
            name: 'GitHub',
            username: 'user@example.com',
            password: 'secret123',
            urls: ['https://github.com'],
            notes: 'Personal',
          },
        },
      ],

      rejected: [],
    });
  });

  it('supports quoted commas, escaped quotes, and multiline fields', () => {
    const csv = [
      'name,username,password,url,notes',
      '"Example, Inc.",user@example.com,"pa""ss,word",https://example.com,"line one',
      'line two"',
    ].join('\n');

    const result = parseCredentialCsv(csv, [testAdapter]);

    expect(result.accepted).toHaveLength(1);

    expect(result.accepted[0]?.draft).toEqual({
      name: 'Example, Inc.',
      username: 'user@example.com',
      password: 'pa"ss,word',
      urls: ['https://example.com'],
      notes: 'line one\nline two',
    });
  });

  it('normalizes header casing and removes a UTF-8 BOM', () => {
    const csv = [
      '\uFEFFName,USERNAME,Password,URL,Notes',
      'Example,user@example.com,password,https://example.com,',
    ].join('\n');

    const result = parseCredentialCsv(csv, [testAdapter]);

    expect(result.accepted).toHaveLength(1);
  });

  it('rejects an unsupported CSV format without exposing row contents', () => {
    expect(() =>
      parseCredentialCsv('foo,bar\nsuper-secret-password,value', [testAdapter]),
    ).toThrowError(
      expect.objectContaining({
        code: 'UNSUPPORTED_FORMAT',
      }),
    );

    try {
      parseCredentialCsv('foo,bar\nsuper-secret-password,value', [testAdapter]);
    } catch (error) {
      expect(error).toBeInstanceOf(CredentialImportError);

      expect((error as Error).message).not.toContain('super-secret-password');
    }
  });

  it('rejects duplicate normalized headers', () => {
    expect(() =>
      parseCredentialCsv(
        'name,Name,password,url,notes\nExample,user,password,https://example.com,',
        [testAdapter],
      ),
    ).toThrowError(
      expect.objectContaining({
        code: 'DUPLICATE_HEADER',
      }),
    );
  });

  it('rejects invalid rows without aborting valid rows', () => {
    const csv = [
      'name,username,password,url,notes',
      ',missing@example.com,password,https://invalid.example,',
      'Valid,valid@example.com,password,https://example.com,',
    ].join('\n');

    const result = parseCredentialCsv(csv, [testAdapter]);

    expect(result.totalRows).toBe(2);

    expect(result.accepted).toHaveLength(1);

    expect(result.accepted[0]?.rowNumber).toBe(3);

    expect(result.rejected).toEqual([
      {
        rowNumber: 2,
        issue: 'MISSING_REQUIRED_FIELD',
      },
    ]);
  });

  it('rejects rows containing oversized fields', () => {
    const oversizedPassword = 'x'.repeat(MAX_IMPORT_FIELD_LENGTH + 1);

    const csv = [
      'name,username,password,url,notes',
      `Example,user@example.com,${oversizedPassword},https://example.com,`,
    ].join('\n');

    const result = parseCredentialCsv(csv, [testAdapter]);

    expect(result.accepted).toHaveLength(0);

    expect(result.rejected).toEqual([
      {
        rowNumber: 2,
        issue: 'FIELD_TOO_LARGE',
      },
    ]);
  });

  it('rejects imports above the row limit', () => {
    const rows = Array.from(
      {
        length: MAX_IMPORT_ROWS + 1,
      },
      (_, index) => `Item ${index},user${index},password,https://example.com,`,
    );

    const csv = ['name,username,password,url,notes', ...rows].join('\n');

    expect(() => parseCredentialCsv(csv, [testAdapter])).toThrowError(
      expect.objectContaining({
        code: 'TOO_MANY_ROWS',
      }),
    );
  });

  it('rejects empty files', () => {
    expect(() => parseCredentialCsv('', [testAdapter])).toThrowError(
      expect.objectContaining({
        code: 'EMPTY_FILE',
      }),
    );
  });
  it('rejects imports with too many headers', () => {
    const headers = Array.from({ length: 100 + 1 }, (_, index) => `field-${index}`);

    expect(() => parseCredentialCsv(headers.join(','), [testAdapter])).toThrowError(
      expect.objectContaining({
        code: 'TOO_MANY_HEADERS',
      }),
    );
  });
  it('accepts a supported CSV containing only headers', () => {
    const result = parseCredentialCsv('name,username,password,url,notes', [testAdapter]);

    expect(result).toEqual({
      adapterId: 'TEST',
      adapterLabel: 'Test CSV',
      totalRows: 0,
      accepted: [],
      rejected: [],
    });
  });
  it('does not expose adapter exception contents', () => {
    const throwingAdapter: CredentialImportAdapter = {
      ...testAdapter,

      mapRow() {
        throw new Error('leaked-password-value');
      },
    };

    const result = parseCredentialCsv(
      [
        'name,username,password,url,notes',
        'Example,user@example.com,super-secret,https://example.com,',
      ].join('\n'),
      [throwingAdapter],
    );

    expect(result.rejected).toEqual([
      {
        rowNumber: 2,
        issue: 'INVALID_ROW',
      },
    ]);

    expect(JSON.stringify(result)).not.toContain('super-secret');
    expect(JSON.stringify(result)).not.toContain('leaked-password-value');
  });
});
