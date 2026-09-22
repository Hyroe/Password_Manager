import { useState } from 'react';
import {
  browserSupportsWebAuthn,
  startRegistration,
  type PublicKeyCredentialCreationOptionsJSON,
} from '@simplewebauthn/browser';

import { apiRequest } from './lib/api';

interface StartRegistrationResponse {
  registrationId: string;
}

interface VerifyEmailResponse {
  registrationToken: string;
}

interface PasskeyOptionsResponse {
  challengeId: string;
  options: PublicKeyCredentialCreationOptionsJSON;
}

interface PasskeyVerifyResponse {
  bootstrapToken: string;
}

export default function App() {
  const [email, setEmail] = useState('');
  const [registrationId, setRegistrationId] = useState<string | null>(null);
  const [verificationToken, setVerificationToken] = useState('');
  const [registrationToken, setRegistrationToken] = useState<string | null>(null);
  const [bootstrapToken, setBootstrapToken] = useState<string | null>(null);

  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const webAuthnSupported = browserSupportsWebAuthn();

  async function startAccountRegistration() {
    setLoading(true);
    setError('');
    setMessage('');

    try {
      const response = await apiRequest<StartRegistrationResponse>('/api/v1/accounts', {
        method: 'POST',
        body: JSON.stringify({
          email,
        }),
      });

      setRegistrationId(response.registrationId);
      setMessage('Registration started. Copy the verification token from the API terminal.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed.');
    } finally {
      setLoading(false);
    }
  }

  async function verifyEmail() {
    if (!registrationId) {
      return;
    }

    setLoading(true);
    setError('');
    setMessage('');

    try {
      const response = await apiRequest<VerifyEmailResponse>('/api/v1/accounts/verify-email', {
        method: 'POST',
        body: JSON.stringify({
          registrationId,
          token: verificationToken,
        }),
      });

      setRegistrationToken(response.registrationToken);
      setMessage('Email verified. You can now create your passkey.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Email verification failed.');
    } finally {
      setLoading(false);
    }
  }

  async function registerPasskey() {
    if (!registrationId || !registrationToken) {
      return;
    }

    setLoading(true);
    setError('');
    setMessage('');

    try {
      const optionsResponse = await apiRequest<PasskeyOptionsResponse>(
        '/api/v1/auth/passkeys/register/options',
        {
          method: 'POST',
          body: JSON.stringify({
            registrationId,
            registrationToken,
          }),
        },
      );

      const credential = await startRegistration({
        optionsJSON: optionsResponse.options,
      });

      const verifyResponse = await apiRequest<PasskeyVerifyResponse>(
        '/api/v1/auth/passkeys/register/verify',
        {
          method: 'POST',
          body: JSON.stringify({
            registrationId,
            registrationToken,
            challengeId: optionsResponse.challengeId,
            credential,
          }),
        },
      );

      setBootstrapToken(verifyResponse.bootstrapToken);
      setMessage('Passkey registered successfully. Ready for cryptographic bootstrap.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Passkey registration failed.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <main>
      <h1>Password Manager</h1>

      {!webAuthnSupported && <p>This browser does not support WebAuthn.</p>}

      {!registrationId && (
        <section>
          <h2>Create account</h2>

          <input
            type="email"
            value={email}
            placeholder="you@example.com"
            onChange={(event) => setEmail(event.target.value)}
          />

          <button type="button" disabled={loading || !email} onClick={startAccountRegistration}>
            Start registration
          </button>
        </section>
      )}

      {registrationId && !registrationToken && (
        <section>
          <h2>Verify email</h2>

          <p>For local development, copy the verification token printed by the API.</p>

          <input
            type="text"
            value={verificationToken}
            placeholder="Verification token"
            onChange={(event) => setVerificationToken(event.target.value)}
          />

          <button type="button" disabled={loading || !verificationToken} onClick={verifyEmail}>
            Verify email
          </button>
        </section>
      )}

      {registrationToken && !bootstrapToken && (
        <section>
          <h2>Create passkey</h2>

          <p>Your browser or operating system should prompt you to create a passkey.</p>

          <button type="button" disabled={loading || !webAuthnSupported} onClick={registerPasskey}>
            Create passkey
          </button>
        </section>
      )}

      {bootstrapToken && (
        <section>
          <h2>Passkey ready</h2>

          <p>The first passkey has been registered successfully.</p>

          <p>
            The temporary bootstrap token is being kept only in browser memory for the next
            onboarding step.
          </p>
        </section>
      )}

      {message && <p>{message}</p>}
      {error && <p role="alert">{error}</p>}
    </main>
  );
}
