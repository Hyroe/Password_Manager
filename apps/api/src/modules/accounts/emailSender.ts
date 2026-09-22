export interface VerificationEmail {
  email: string;
  registrationId: string;
  token: string;
}

export interface EmailSender {
  sendVerificationEmail(message: VerificationEmail): Promise<void>;
}

export const noopEmailSender: EmailSender = {
  async sendVerificationEmail() {},
};
