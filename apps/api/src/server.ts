import { createApp } from './app.js';

import { getEnvironment } from './config/env.js';

import { consoleEmailSender } from './modules/accounts/consoleEmailSender.js';

import { consoleStructuredLogger } from './observability/logger.js';

const environment = getEnvironment();

const logger = consoleStructuredLogger;

const app = createApp({
  emailSender: consoleEmailSender,
  logger,
});

app.listen(environment.PORT, () => {
  logger.write({
    timestamp: new Date().toISOString(),
    level: 'info',
    event: 'api.started',
    port: environment.PORT,
  });
});
