import { describe, expect, it } from 'vitest';

import { parseCredentialCsv } from '../credentialImport';

import { chromiumCredentialImportAdapter } from './chromium';

describe('chromiumCredentialImportAdapter', () => {
  it('detects url, username, and password headers', () => {
    expect(
      chromiumCredentialImportAdapter.canParse(['name', 'url', 'username', 'password', 'note']),
    ).toBe(true);
  });

  it('accepts login as a username header alias', () => {
    expect(chromiumCredentialImportAdapter.canParse(['url', 'login', 'password'])).toBe(true);
  });

  it('does not detect unrelated CSV formats', () => {
    expect(chromiumCredentialImportAdapter.canParse(['website', 'account', 'secret'])).toBe(false);
  });

  it('maps a Chromium credential to LoginItemDraft', () => {
    const result = parseCredentialCsv(
      [
        'name,url,username,password,note',
        'GitHub,https://github.com,user@example.com,secret-password,Personal account',
      ].join('\n'),
      [chromiumCredentialImportAdapter],
    );

    expect(result.adapterId).toBe('CHROMIUM_CSV');

    expect(result.accepted).toEqual([
      {
        rowNumber: 2,

        draft: {
          name: 'GitHub',
          username: 'user@example.com',
          password: 'secret-password',
          urls: ['https://github.com'],
          notes: 'Personal account',
        },
      },
    ]);

    expect(result.rejected).toEqual([]);
  });

  it('derives the login name from the URL when no name column exists', () => {
    const result = parseCredentialCsv(
      ['url,username,password', 'https://www.example.com/login,user@example.com,password'].join(
        '\n',
      ),
      [chromiumCredentialImportAdapter],
    );

    expect(result.accepted[0]?.draft.name).toBe('example.com');
  });

  it('preserves password whitespace exactly', () => {
    const result = parseCredentialCsv(
      ['url,username,password', 'https://example.com,user@example.com,"  secret password  "'].join(
        '\n',
      ),
      [chromiumCredentialImportAdapter],
    );

    expect(result.accepted[0]?.draft.password).toBe('  secret password  ');
  });

  it('allows an empty username', () => {
    const result = parseCredentialCsv(
      ['url,username,password', 'https://example.com,,secret-password'].join('\n'),
      [chromiumCredentialImportAdapter],
    );

    expect(result.accepted).toHaveLength(1);

    expect(result.accepted[0]?.draft.username).toBe('');
  });

  it('rejects a row without a URL', () => {
    const result = parseCredentialCsv(
      ['url,username,password', ',user@example.com,secret-password'].join('\n'),
      [chromiumCredentialImportAdapter],
    );

    expect(result.accepted).toHaveLength(0);

    expect(result.rejected).toEqual([
      {
        rowNumber: 2,
        issue: 'MISSING_REQUIRED_FIELD',
      },
    ]);
  });

  it('rejects a row without a password', () => {
    const result = parseCredentialCsv(
      ['url,username,password', 'https://example.com,user@example.com,'].join('\n'),
      [chromiumCredentialImportAdapter],
    );

    expect(result.accepted).toHaveLength(0);

    expect(result.rejected).toEqual([
      {
        rowNumber: 2,
        issue: 'MISSING_REQUIRED_FIELD',
      },
    ]);
  });

  it('uses note before other supported note aliases', () => {
    const result = parseCredentialCsv(
      [
        'url,username,password,comment,notes,note',
        'https://example.com,user,password,comment value,notes value,note value',
      ].join('\n'),
      [chromiumCredentialImportAdapter],
    );

    expect(result.accepted[0]?.draft.notes).toBe('note value');
  });

  it('supports login and comments aliases', () => {
    const result = parseCredentialCsv(
      [
        'url,login,password,comments',
        'https://example.com,user@example.com,password,Imported note',
      ].join('\n'),
      [chromiumCredentialImportAdapter],
    );

    expect(result.accepted[0]?.draft).toEqual({
      name: 'example.com',
      username: 'user@example.com',
      password: 'password',
      urls: ['https://example.com'],
      notes: 'Imported note',
    });
  });
  it('parses a Chrome password export fixture', () => {
    const csv = [
      'name,url,username,password,note',
      'GitHub,https://github.com,octocat@example.com,FakeGitHubPassword!123,Cuenta de desarrollo',
      'Google,https://accounts.google.com,user.fake@gmail.com,MyS3cretP@ss!,Correo principal',
      'Amazon,https://www.amazon.com,shopper@example.com,Amaz0n#2024,Compras personales',
      'Netflix,https://www.netflix.com,streamer@example.com,netflix123,Plan familiar',
      'Twitter,https://twitter.com,@fakehandle,Tw1tter!Pass,Cuenta secundaria',
      'LinkedIn,https://www.linkedin.com,in/john-doe,LinkedIn$2024,Perfil profesional',
      'Facebook,https://www.facebook.com,john.doe.123,FB_P@ssw0rd,Cuenta antigua',
    ].join('\n');

    const result = parseCredentialCsv(csv, [chromiumCredentialImportAdapter]);

    expect(result.adapterId).toBe('CHROMIUM_CSV');
    expect(result.totalRows).toBe(7);
    expect(result.accepted).toHaveLength(7);
    expect(result.rejected).toHaveLength(0);

    expect(result.accepted[0]?.draft).toEqual({
      name: 'GitHub',
      username: 'octocat@example.com',
      password: 'FakeGitHubPassword!123',
      urls: ['https://github.com'],
      notes: 'Cuenta de desarrollo',
    });

    expect(result.accepted[6]?.draft).toEqual({
      name: 'Facebook',
      username: 'john.doe.123',
      password: 'FB_P@ssw0rd',
      urls: ['https://www.facebook.com'],
      notes: 'Cuenta antigua',
    });
  });
});
