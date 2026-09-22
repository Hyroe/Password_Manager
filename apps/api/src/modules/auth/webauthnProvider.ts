import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  type CredentialDeviceType,
  type PublicKeyCredentialCreationOptionsJSON,
  type RegistrationResponseJSON,
  type WebAuthnCredential,
} from '@simplewebauthn/server';

import { webAuthnConfig } from '../../config/webauthn.js';

export interface VerifiedPasskeyRegistration {
  credential: WebAuthnCredential;
  deviceType: CredentialDeviceType;
  backedUp: boolean;
}

interface GenerateRegistrationInput {
  userName: string;
  userDisplayName: string;
  userID: Uint8Array;
}

interface VerifyRegistrationInput {
  response: RegistrationResponseJSON;
  expectedChallenge: string;
}

export interface WebAuthnProvider {
  generateRegistrationOptions(
    input: GenerateRegistrationInput,
  ): Promise<PublicKeyCredentialCreationOptionsJSON>;

  verifyRegistrationResponse(input: VerifyRegistrationInput): Promise<VerifiedPasskeyRegistration>;
}

export const simpleWebAuthnProvider: WebAuthnProvider = {
  async generateRegistrationOptions(input) {
    const userID = new Uint8Array(input.userID.byteLength);
    userID.set(input.userID);

    return generateRegistrationOptions({
      rpName: webAuthnConfig.rpName,
      rpID: webAuthnConfig.rpID,

      userName: input.userName,
      userDisplayName: input.userDisplayName,
      userID: userID,

      attestationType: 'none',

      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required',
      },
    });
  },

  async verifyRegistrationResponse(input) {
    const verification = await verifyRegistrationResponse({
      response: input.response,
      expectedChallenge: input.expectedChallenge,
      expectedOrigin: webAuthnConfig.origin,
      expectedRPID: webAuthnConfig.rpID,
      requireUserVerification: true,
    });

    if (!verification.verified || !verification.registrationInfo) {
      throw new Error('WEBAUTHN_VERIFICATION_FAILED');
    }

    const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;

    return {
      credential,
      deviceType: credentialDeviceType,
      backedUp: credentialBackedUp,
    };
  },
};
