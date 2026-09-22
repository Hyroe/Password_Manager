import 'dotenv/config';

import { createApp } from './app.js';
import { consoleEmailSender } from './modules/accounts/consoleEmailSender.js';

const port = Number(process.env.PORT ?? 3000);

const app = createApp({
  emailSender: consoleEmailSender,
});

app.listen(port, () => {
  console.log(`API listening on port ${port}`);
});
