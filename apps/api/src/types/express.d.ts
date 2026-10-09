export {};

declare global {
  namespace Express {
    interface Request {
      auth?: {
        sessionId: string;
        userId: string;
        email: string;

        clientKind: 'WEB' | 'BROWSER_EXTENSION';
        transport: 'COOKIE' | 'BEARER';

        absoluteExpiresAt: Date;
      };
    }
  }
}
