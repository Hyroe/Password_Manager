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
