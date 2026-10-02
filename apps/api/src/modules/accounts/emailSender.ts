export interface VerificationEmail {
  email: string;
  registrationId: string;
  token: string;
}

export interface EmailSender {
  /*
   * Production must explicitly opt in.
   *
   * Missing/false means that the sender is intended
   * only for development, testing, or placeholders.
   */
  readonly productionSafe?: boolean;

  sendVerificationEmail(message: VerificationEmail): Promise<void>;
}

export const noopEmailSender: EmailSender = {
  productionSafe: false,

  async sendVerificationEmail() {},
};
