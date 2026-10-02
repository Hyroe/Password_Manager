import type { EmailSender } from './emailSender.js';

export const consoleEmailSender: EmailSender = {
  productionSafe: false,

  async sendVerificationEmail(message) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('Console email sender cannot be used in production');
    }

    console.info('');
    console.info('----------------------------------------');
    console.info('LOCAL EMAIL VERIFICATION');
    console.info(`Email: ${message.email}`);
    console.info(`Registration ID: ${message.registrationId}`);
    console.info(`Token: ${message.token}`);
    console.info('----------------------------------------');
    console.info('');
  },
};
