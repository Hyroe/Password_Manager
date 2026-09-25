export interface RecoveryKit {
  format: 'PM_RECOVERY_KIT';
  formatVersion: 1;

  createdAt: string;

  account: {
    email: string;
    cryptoProfileId: string;
    vaultId: string;
  };

  crypto: {
    protocolVersion: number;
    kdfProfileVersion: number;
  };

  secrets: {
    accountSecret: string;
    recoveryKey: string;
  };
}

export function downloadRecoveryKit(recoveryKit: RecoveryKit): void {
  const contents = JSON.stringify(recoveryKit, null, 2);

  const blob = new Blob([contents], {
    type: 'application/json;charset=utf-8',
  });

  const url = URL.createObjectURL(blob);

  const anchor = document.createElement('a');

  anchor.href = url;
  anchor.download = 'password-manager-recovery-kit.json';

  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();

  URL.revokeObjectURL(url);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

export async function readRecoveryKit(file: File): Promise<RecoveryKit> {
  if (file.size > 64 * 1024) {
    throw new Error('Recovery Kit file is unexpectedly large.');
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(await file.text());
  } catch {
    throw new Error('Recovery Kit is not valid JSON.');
  }

  if (!isRecord(parsed) || parsed.format !== 'PM_RECOVERY_KIT' || parsed.formatVersion !== 1) {
    throw new Error('Unsupported Recovery Kit.');
  }

  const account = parsed.account;
  const crypto = parsed.crypto;
  const secrets = parsed.secrets;

  if (
    !isRecord(account) ||
    typeof account.email !== 'string' ||
    typeof account.cryptoProfileId !== 'string' ||
    typeof account.vaultId !== 'string'
  ) {
    throw new Error('Recovery Kit account data is invalid.');
  }

  if (
    !isRecord(crypto) ||
    typeof crypto.protocolVersion !== 'number' ||
    typeof crypto.kdfProfileVersion !== 'number'
  ) {
    throw new Error('Recovery Kit crypto metadata is invalid.');
  }

  if (
    !isRecord(secrets) ||
    typeof secrets.accountSecret !== 'string' ||
    typeof secrets.recoveryKey !== 'string'
  ) {
    throw new Error('Recovery Kit secrets are invalid.');
  }

  return parsed as unknown as RecoveryKit;
}
