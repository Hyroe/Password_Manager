import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type WebAuthnCredential,
} from '@simplewebauthn/server';

import { webAuthnConfig } from '../../config/webauthn.js';

export interface VerifiedPasskeyAuthentication {
  newCounter: number;
}

interface VerifyAuthenticationInput {
  response: AuthenticationResponseJSON;
  expectedChallenge: string;
  credential: WebAuthnCredential;
}

export interface PasskeyAuthenticationProvider {
  generateAuthenticationOptions(): Promise<PublicKeyCredentialRequestOptionsJSON>;

  verifyAuthenticationResponse(
    input: VerifyAuthenticationInput,
  ): Promise<VerifiedPasskeyAuthentication>;
}

export const simplePasskeyAuthenticationProvider: PasskeyAuthenticationProvider = {
  async generateAuthenticationOptions() {
    return generateAuthenticationOptions({
      rpID: webAuthnConfig.rpID,

      /*
       * allowCredentials intentionally omitted.
       *
       * Registration requires discoverable credentials,
       * so the authenticator can identify the account.
       */
      userVerification: 'required',
    });
  },

  async verifyAuthenticationResponse(input) {
    const verification = await verifyAuthenticationResponse({
      response: input.response,

      expectedChallenge: input.expectedChallenge,

      expectedOrigin: webAuthnConfig.origin,

      expectedRPID: webAuthnConfig.rpID,

      credential: input.credential,

      requireUserVerification: true,
    });

    if (!verification.verified) {
      throw new Error('WEBAUTHN_AUTHENTICATION_FAILED');
    }

    return {
      newCounter: verification.authenticationInfo.newCounter,
    };
  },
};
