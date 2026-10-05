import type { UnlockedVault } from './cryptoCore';

import type { AcceptedCredentialImportRow } from './credentialImport';

import { createLoginVaultItem } from './vaultItems';

export type CredentialImportFailureAction = 'CONTINUE' | 'ABORT';

export interface CredentialImportExecutionResult {
  totalRows: number;

  importedRows: number[];
  failedRows: number[];

  aborted: boolean;
  abortedAtRow: number | null;
}
export interface CredentialImportExecutionProgress {
  completedCount: number;
  totalCount: number;

  importedCount: number;
  failedCount: number;
}

interface ExecuteCredentialImportOptions {
  shouldContinue?: () => boolean;

  onFailure?: (error: unknown, rowNumber: number) => CredentialImportFailureAction;

  onProgress?: (progress: CredentialImportExecutionProgress) => void;
}

export async function executeVaultCredentialImport(
  vault: UnlockedVault,
  vaultId: string,
  rows: readonly AcceptedCredentialImportRow[],
  options: ExecuteCredentialImportOptions = {},
): Promise<CredentialImportExecutionResult> {
  const importedRows: number[] = [];
  const failedRows: number[] = [];

  for (const row of rows) {
    if (options.shouldContinue && !options.shouldContinue()) {
      return {
        totalRows: rows.length,

        importedRows,
        failedRows,

        aborted: true,
        abortedAtRow: row.rowNumber,
      };
    }

    try {
      /*
       * Reuse the normal vault creation path.
       *
       * The imported plaintext is encrypted locally before
       * encrypted item material is persisted by the API.
       */
      await createLoginVaultItem(vault, vaultId, row.draft);

      importedRows.push(row.rowNumber);

      options.onProgress?.({
        completedCount: importedRows.length + failedRows.length,
        totalCount: rows.length,

        importedCount: importedRows.length,
        failedCount: failedRows.length,
      });
    } catch (error) {
      const action = options.onFailure?.(error, row.rowNumber) ?? 'CONTINUE';

      if (action === 'ABORT') {
        return {
          totalRows: rows.length,

          importedRows,
          failedRows,

          aborted: true,
          abortedAtRow: row.rowNumber,
        };
      }

      failedRows.push(row.rowNumber);

      options.onProgress?.({
        completedCount: importedRows.length + failedRows.length,
        totalCount: rows.length,

        importedCount: importedRows.length,
        failedCount: failedRows.length,
      });
    }
  }

  return {
    totalRows: rows.length,

    importedRows,
    failedRows,

    aborted: false,
    abortedAtRow: null,
  };
}
