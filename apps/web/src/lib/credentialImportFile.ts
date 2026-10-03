import {
  CredentialImportError,
  parseCredentialCsv,
  type CredentialImportAdapter,
  type CredentialImportResult,
} from './credentialImport';

export const MAX_IMPORT_FILE_BYTES = 10 * 1024 * 1024;

export interface CredentialImportReadableFile {
  readonly size: number;

  text(): Promise<string>;
}

export async function readCredentialImportFile(
  file: CredentialImportReadableFile,
  adapters: readonly CredentialImportAdapter[],
): Promise<CredentialImportResult> {
  if (file.size === 0) {
    throw new CredentialImportError('EMPTY_FILE', 'The selected CSV is empty.');
  }

  if (file.size > MAX_IMPORT_FILE_BYTES) {
    throw new CredentialImportError('FILE_TOO_LARGE', 'The selected CSV is too large to import.');
  }

  let csv: string;

  try {
    csv = await file.text();
  } catch {
    throw new CredentialImportError('FILE_READ_FAILED', 'The selected CSV could not be read.');
  }

  return parseCredentialCsv(csv, adapters);
}
