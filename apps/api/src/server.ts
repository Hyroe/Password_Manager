import { createApp } from './app.js';

import { getEnvironment } from './config/env.js';

import { consoleEmailSender } from './modules/accounts/consoleEmailSender.js';

const environment = getEnvironment();

const app = createApp({
  emailSender: consoleEmailSender,
});

app.listen(environment.PORT, () => {
  console.log(`API listening on port ${environment.PORT}`);
});
