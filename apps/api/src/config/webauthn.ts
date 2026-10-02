import { getEnvironment } from './env.js';

const environment = getEnvironment();

export const webAuthnConfig = {
  rpName: environment.WEBAUTHN_RP_NAME,

  rpID: environment.WEBAUTHN_RP_ID,

  origin: environment.WEBAUTHN_ORIGIN,
};
