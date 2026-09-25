export {};

declare global {
  namespace Express {
    interface Request {
      auth?: {
        sessionId: string;
        userId: string;
        email: string;
        absoluteExpiresAt: Date;
      };
    }
  }
}
