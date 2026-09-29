import express from 'express';
import { resolve } from 'node:path';

import { createApp } from './app.js';
import type { EmailSender, VerificationEmail } from './modules/accounts/emailSender.js';

if (process.env.NODE_ENV === 'production') {
  throw new Error('The E2E server must never run in production.');
}

const PORT = Number(process.env.PORT ?? 5173);

const verificationEmails = new Map<string, VerificationEmail>();

const emailSender: EmailSender = {
  async sendVerificationEmail(message) {
    verificationEmails.set(message.registrationId, message);
  },
};

const app = createApp({
  emailSender,
});

/*
 * E2E-only test bridge.
 *
 * This route does not exist in createApp()
 * and therefore cannot exist in the normal
 * production server.
 */
app.get('/__e2e/verification/:registrationId', (req, res) => {
  const message = verificationEmails.get(req.params.registrationId);

  if (!message) {
    res.status(404).json({
      error: {
        code: 'E2E_VERIFICATION_NOT_FOUND',
        message: 'Verification message not found.',
      },
    });

    return;
  }

  res.status(200).json({
    token: message.token,
  });
});

const webDist = resolve(process.cwd(), '../web/dist');

app.use(express.static(webDist));

/*
 * SPA fallback after all API and E2E routes.
 */
app.use((_req, res) => {
  res.sendFile(resolve(webDist, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Password Manager E2E server listening on http://localhost:${PORT}`);
});
