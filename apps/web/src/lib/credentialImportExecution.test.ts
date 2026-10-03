import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { UnlockedVault } from './cryptoCore';

import type { AcceptedCredentialImportRow } from './credentialImport';

import { createLoginVaultItem } from './vaultItems';

import { executeVaultCredentialImport } from './credentialImportExecution';

vi.mock('./vaultItems', () => ({
  createLoginVaultItem: vi.fn(),
}));

const mockedCreateLoginVaultItem = vi.mocked(createLoginVaultItem);

const vault = {} as UnlockedVault;

function createRows(): AcceptedCredentialImportRow[] {
  return [
    {
      rowNumber: 2,
      draft: {
        name: 'One',
        username: 'one@example.com',
        password: 'password-one',
        urls: ['https://one.example'],
        notes: '',
      },
    },
    {
      rowNumber: 3,
      draft: {
        name: 'Two',
        username: 'two@example.com',
        password: 'password-two',
        urls: ['https://two.example'],
        notes: '',
      },
    },
    {
      rowNumber: 4,
      draft: {
        name: 'Three',
        username: 'three@example.com',
        password: 'password-three',
        urls: ['https://three.example'],
        notes: '',
      },
    },
  ];
}

describe('executeVaultCredentialImport', () => {
  beforeEach(() => {
    mockedCreateLoginVaultItem.mockReset();
  });

  it('imports credentials through the normal vault creation path', async () => {
    mockedCreateLoginVaultItem.mockResolvedValue({} as never);

    const rows = createRows();

    const result = await executeVaultCredentialImport(vault, 'vault-1', rows);

    expect(mockedCreateLoginVaultItem).toHaveBeenCalledTimes(3);

    expect(mockedCreateLoginVaultItem).toHaveBeenNthCalledWith(1, vault, 'vault-1', rows[0]?.draft);

    expect(result).toEqual({
      totalRows: 3,
      importedRows: [2, 3, 4],
      failedRows: [],
      aborted: false,
      abortedAtRow: null,
    });
  });

  it('continues after an individual row failure', async () => {
    mockedCreateLoginVaultItem
      .mockResolvedValueOnce({} as never)
      .mockRejectedValueOnce(new Error('row failed'))
      .mockResolvedValueOnce({} as never);

    const result = await executeVaultCredentialImport(vault, 'vault-1', createRows());

    expect(mockedCreateLoginVaultItem).toHaveBeenCalledTimes(3);

    expect(result).toEqual({
      totalRows: 3,
      importedRows: [2, 4],
      failedRows: [3],
      aborted: false,
      abortedAtRow: null,
    });
  });

  it('can abort execution after a classified failure', async () => {
    const sessionExpired = new Error('potential-secret-error-message');

    mockedCreateLoginVaultItem
      .mockResolvedValueOnce({} as never)
      .mockRejectedValueOnce(sessionExpired);

    const result = await executeVaultCredentialImport(vault, 'vault-1', createRows(), {
      onFailure(error) {
        return error === sessionExpired ? 'ABORT' : 'CONTINUE';
      },
    });

    expect(mockedCreateLoginVaultItem).toHaveBeenCalledTimes(2);

    expect(result).toEqual({
      totalRows: 3,
      importedRows: [2],
      failedRows: [],
      aborted: true,
      abortedAtRow: 3,
    });

    expect(JSON.stringify(result)).not.toContain('potential-secret-error-message');
  });

  it('stops before starting another row when the import is cancelled', async () => {
    let continueImport = true;

    mockedCreateLoginVaultItem.mockImplementation(async () => {
      continueImport = false;

      return {} as never;
    });

    const result = await executeVaultCredentialImport(vault, 'vault-1', createRows(), {
      shouldContinue() {
        return continueImport;
      },
    });

    expect(mockedCreateLoginVaultItem).toHaveBeenCalledTimes(1);

    expect(result).toEqual({
      totalRows: 3,
      importedRows: [2],
      failedRows: [],
      aborted: true,
      abortedAtRow: 3,
    });
  });

  it('executes vault writes sequentially', async () => {
    let inFlight = 0;
    let maximumInFlight = 0;

    mockedCreateLoginVaultItem.mockImplementation(async () => {
      inFlight += 1;

      maximumInFlight = Math.max(maximumInFlight, inFlight);

      await Promise.resolve();

      inFlight -= 1;

      return {} as never;
    });

    await executeVaultCredentialImport(vault, 'vault-1', createRows());

    expect(maximumInFlight).toBe(1);
  });
});
