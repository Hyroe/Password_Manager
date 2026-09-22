const rpName = process.env.WEBAUTHN_RP_NAME;
const rpID = process.env.WEBAUTHN_RP_ID;
const origin = process.env.WEBAUTHN_ORIGIN;

if (!rpName || !rpID || !origin) {
  throw new Error('WebAuthn configuration is required');
}

export const webAuthnConfig = {
  rpName,
  rpID,
  origin,
};
