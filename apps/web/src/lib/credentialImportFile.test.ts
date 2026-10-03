import { describe, expect, it, vi } from 'vitest';

import { chromiumCredentialImportAdapter } from './credentialImportAdapters/chromium';

import { MAX_IMPORT_FILE_BYTES, readCredentialImportFile } from './credentialImportFile';

describe('readCredentialImportFile', () => {
  it('rejects oversized files before reading their contents', async () => {
    const text = vi.fn(async () => {
      throw new Error('file contents should not be read');
    });

    await expect(
      readCredentialImportFile(
        {
          size: MAX_IMPORT_FILE_BYTES + 1,
          text,
        },
        [chromiumCredentialImportAdapter],
      ),
    ).rejects.toMatchObject({
      code: 'FILE_TOO_LARGE',
    });

    expect(text).not.toHaveBeenCalled();
  });

  it('rejects empty files before reading their contents', async () => {
    const text = vi.fn(async () => '');

    await expect(
      readCredentialImportFile(
        {
          size: 0,
          text,
        },
        [chromiumCredentialImportAdapter],
      ),
    ).rejects.toMatchObject({
      code: 'EMPTY_FILE',
    });

    expect(text).not.toHaveBeenCalled();
  });

  it('collapses file read failures into a safe error', async () => {
    const text = vi.fn(async () => {
      throw new Error('secret-file-path-or-content');
    });

    try {
      await readCredentialImportFile(
        {
          size: 1024,
          text,
        },
        [chromiumCredentialImportAdapter],
      );
    } catch (error) {
      expect(error).toMatchObject({
        code: 'FILE_READ_FAILED',
      });

      expect((error as Error).message).not.toContain('secret-file-path-or-content');
    }
  });

  it('reads and parses a Chromium CSV', async () => {
    const csv = [
      'name,url,username,password,note',
      'Example,https://example.com,user@example.com,FakePassword123!,Test account',
    ].join('\n');

    const result = await readCredentialImportFile(
      {
        size: new Blob([csv]).size,
        text: async () => csv,
      },
      [chromiumCredentialImportAdapter],
    );

    expect(result.adapterId).toBe('CHROMIUM_CSV');
    expect(result.accepted).toHaveLength(1);

    expect(result.accepted[0]?.draft.password).toBe('FakePassword123!');
  });
});
