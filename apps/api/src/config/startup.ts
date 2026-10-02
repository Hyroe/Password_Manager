import type { EmailSender } from '../modules/accounts/emailSender.js';

import type { Environment } from './env.js';

interface RuntimeDependencies {
  emailSender: EmailSender;
}

export function assertRuntimeDependencies(
  environment: Environment,
  dependencies: RuntimeDependencies,
): void {
  if (environment.NODE_ENV === 'production' && dependencies.emailSender.productionSafe !== true) {
    throw new Error('Production-safe email delivery is required in production.');
  }
}
