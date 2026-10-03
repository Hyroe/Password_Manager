import type { CredentialImportAdapter } from '../credentialImport';

import { chromiumCredentialImportAdapter } from './chromium';

export { chromiumCredentialImportAdapter } from './chromium';

export const credentialImportAdapters: readonly CredentialImportAdapter[] = [
  chromiumCredentialImportAdapter,
];
