import { useEffect, useRef, useState } from 'react';

import {
  browserSupportsWebAuthn,
  startRegistration,
  type PublicKeyCredentialCreationOptionsJSON,
} from '@simplewebauthn/browser';

import './App.css';

import { apiRequest } from './lib/api';
import { createAccountBootstrap, type AccountBootstrapResult } from './lib/cryptoCore';
import { bytesToBase64Url, wipeBytes } from './lib/encoding';
import { downloadRecoveryKit, type RecoveryKit } from './lib/recoveryKit';

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

interface CryptoBootstrapOptionsResponse {
  bootstrapContextId: string;

  cryptoProfileId: string;
  vaultId: string;

  protocolVersion: number;

  kdf: {
    algorithm: 'ARGON2ID';
    profileVersion: number;

    memoryKib: number;
    iterations: number;
    parallelism: number;

    saltBytes: number;
  };

  envelope: {
    version: number;

    rootKeyAad: string;
    recoveryRootKeyAad: string;
    vaultKeyAad: string;
  };
}

interface CompleteBootstrapResponse {
  userId: string;
  vaultId: string;
  status: 'ACTIVE';
}

export default function App() {
  const [email, setEmail] = useState('');

  const [registrationId, setRegistrationId] = useState<string | null>(null);

  const [verificationToken, setVerificationToken] = useState('');

  const [registrationToken, setRegistrationToken] = useState<string | null>(null);

  const [bootstrapToken, setBootstrapToken] = useState<string | null>(null);

  const [bootstrapOptions, setBootstrapOptions] = useState<CryptoBootstrapOptionsResponse | null>(
    null,
  );

  const [recoveryKitDownloaded, setRecoveryKitDownloaded] = useState(false);

  const [completedAccount, setCompletedAccount] = useState<CompleteBootstrapResponse | null>(null);

  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const masterPasswordRef = useRef<HTMLInputElement>(null);

  const confirmMasterPasswordRef = useRef<HTMLInputElement>(null);

  const bootstrapRef = useRef<AccountBootstrapResult | null>(null);

  const webAuthnSupported = browserSupportsWebAuthn();

  useEffect(() => {
    return () => {
      const bootstrap = bootstrapRef.current;

      if (bootstrap) {
        bootstrap.clear();
        bootstrap.free();

        bootstrapRef.current = null;
      }
    };
  }, []);

  function resetMessages() {
    setError('');
    setMessage('');
  }

  async function startAccountRegistration() {
    setLoading(true);
    resetMessages();

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
    resetMessages();

    try {
      const response = await apiRequest<VerifyEmailResponse>('/api/v1/accounts/verify-email', {
        method: 'POST',
        body: JSON.stringify({
          registrationId,
          token: verificationToken,
        }),
      });

      setRegistrationToken(response.registrationToken);

      setMessage('Email verified. Create your passkey.');
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
    resetMessages();

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

      setMessage('Passkey registered. Now create your Master Password.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Passkey registration failed.');
    } finally {
      setLoading(false);
    }
  }

  async function prepareCryptoBootstrap() {
    if (!registrationId || !bootstrapToken) {
      return;
    }

    const masterPassword = masterPasswordRef.current?.value ?? '';

    const confirmation = confirmMasterPasswordRef.current?.value ?? '';

    resetMessages();

    if (masterPassword.length < 12) {
      setError('Master Password must contain at least 12 characters.');

      return;
    }

    if (masterPassword !== confirmation) {
      setError('Master Password confirmation does not match.');

      return;
    }

    setLoading(true);

    try {
      const options = await apiRequest<CryptoBootstrapOptionsResponse>(
        '/api/v1/accounts/crypto/options',
        {
          method: 'POST',
          body: JSON.stringify({
            registrationId,
            bootstrapToken,
          }),
        },
      );

      const encoder = new TextEncoder();

      const bootstrap = await createAccountBootstrap({
        masterPassword,

        rootKeyAad: encoder.encode(options.envelope.rootKeyAad),

        recoveryRootKeyAad: encoder.encode(options.envelope.recoveryRootKeyAad),

        vaultKeyAad: encoder.encode(options.envelope.vaultKeyAad),
      });

      const policyMatches =
        bootstrap.protocol_version === options.protocolVersion &&
        bootstrap.kdf_profile_version === options.kdf.profileVersion &&
        bootstrap.argon2_memory_kib === options.kdf.memoryKib &&
        bootstrap.argon2_iterations === options.kdf.iterations &&
        bootstrap.argon2_parallelism === options.kdf.parallelism;

      if (!policyMatches) {
        bootstrap.clear();
        bootstrap.free();

        throw new Error('Crypto protocol mismatch between client and server.');
      }

      const previousBootstrap = bootstrapRef.current;

      if (previousBootstrap) {
        previousBootstrap.clear();
        previousBootstrap.free();
      }

      bootstrapRef.current = bootstrap;

      setBootstrapOptions(options);
      setRecoveryKitDownloaded(false);

      setMessage(
        'Cryptographic material created locally. Save your Recovery Kit before activating the account.',
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Cryptographic bootstrap failed.');
    } finally {
      if (masterPasswordRef.current) {
        masterPasswordRef.current.value = '';
      }

      if (confirmMasterPasswordRef.current) {
        confirmMasterPasswordRef.current.value = '';
      }

      setLoading(false);
    }
  }

  function saveRecoveryKit() {
    const bootstrap = bootstrapRef.current;

    if (!bootstrap || !bootstrapOptions) {
      return;
    }

    resetMessages();

    const accountSecret = bootstrap.account_secret();

    const recoveryKey = bootstrap.recovery_key();

    try {
      const recoveryKit: RecoveryKit = {
        format: 'PM_RECOVERY_KIT',
        formatVersion: 1,

        createdAt: new Date().toISOString(),

        account: {
          email,
          cryptoProfileId: bootstrapOptions.cryptoProfileId,
          vaultId: bootstrapOptions.vaultId,
        },

        crypto: {
          protocolVersion: bootstrapOptions.protocolVersion,

          kdfProfileVersion: bootstrapOptions.kdf.profileVersion,
        },

        secrets: {
          accountSecret: bytesToBase64Url(accountSecret),

          recoveryKey: bytesToBase64Url(recoveryKey),
        },
      };

      downloadRecoveryKit(recoveryKit);

      setRecoveryKitDownloaded(true);

      setMessage(
        'Recovery Kit saved. Keep it offline and secure. You can now activate the account.',
      );
    } finally {
      wipeBytes(accountSecret);
      wipeBytes(recoveryKey);
    }
  }

  async function activateAccount() {
    const bootstrap = bootstrapRef.current;

    if (
      !bootstrap ||
      !bootstrapOptions ||
      !registrationId ||
      !bootstrapToken ||
      !recoveryKitDownloaded
    ) {
      return;
    }

    setLoading(true);
    resetMessages();

    const kdfSalt = bootstrap.kdf_salt();

    const rootKeyEnvelope = bootstrap.root_key_envelope();

    const recoveryRootKeyEnvelope = bootstrap.recovery_root_key_envelope();

    const vaultKeyEnvelope = bootstrap.vault_key_envelope();

    try {
      const response = await apiRequest<CompleteBootstrapResponse>(
        '/api/v1/accounts/crypto/complete',
        {
          method: 'POST',

          body: JSON.stringify({
            registrationId,
            bootstrapToken,

            bootstrapContextId: bootstrapOptions.bootstrapContextId,

            protocolVersion: bootstrapOptions.protocolVersion,

            kdf: {
              algorithm: bootstrapOptions.kdf.algorithm,

              profileVersion: bootstrapOptions.kdf.profileVersion,

              memoryKib: bootstrapOptions.kdf.memoryKib,

              iterations: bootstrapOptions.kdf.iterations,

              parallelism: bootstrapOptions.kdf.parallelism,

              salt: bytesToBase64Url(kdfSalt),
            },

            envelope: {
              version: bootstrapOptions.envelope.version,

              rootKey: bytesToBase64Url(rootKeyEnvelope),

              recoveryRootKey: bytesToBase64Url(recoveryRootKeyEnvelope),

              vaultKey: bytesToBase64Url(vaultKeyEnvelope),
            },
          }),
        },
      );

      bootstrap.clear();
      bootstrap.free();

      bootstrapRef.current = null;

      setBootstrapToken(null);
      setRegistrationToken(null);
      setVerificationToken('');

      setCompletedAccount(response);

      setMessage('Account activated successfully.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Account activation failed.');
    } finally {
      wipeBytes(kdfSalt);
      wipeBytes(rootKeyEnvelope);
      wipeBytes(recoveryRootKeyEnvelope);
      wipeBytes(vaultKeyEnvelope);

      setLoading(false);
    }
  }

  return (
    <main>
      <h1>Password Manager</h1>

      {!webAuthnSupported && <p role="alert">This browser does not support WebAuthn.</p>}

      {!registrationId && (
        <section>
          <h2>Create account</h2>

          <input
            type="email"
            value={email}
            placeholder="you@example.com"
            autoComplete="email"
            onChange={(event) => setEmail(event.target.value)}
          />

          <button type="button" disabled={loading || !email} onClick={startAccountRegistration}>
            Start registration
          </button>
        </section>
      )}

      {registrationId && !registrationToken && !bootstrapToken && !completedAccount && (
        <section>
          <h2>Verify email</h2>

          <p>Copy the local verification token from the API terminal.</p>

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

      {registrationToken && !bootstrapToken && !completedAccount && (
        <section>
          <h2>Create passkey</h2>

          <p>Windows Hello or your authenticator will ask you to create a passkey.</p>

          <button type="button" disabled={loading || !webAuthnSupported} onClick={registerPasskey}>
            Create passkey
          </button>
        </section>
      )}

      {bootstrapToken && !bootstrapOptions && !completedAccount && (
        <section>
          <h2>Protect your vault</h2>

          <p>Your Master Password never leaves this browser.</p>

          <input
            ref={masterPasswordRef}
            type="password"
            placeholder="Master Password"
            autoComplete="new-password"
          />

          <input
            ref={confirmMasterPasswordRef}
            type="password"
            placeholder="Confirm Master Password"
            autoComplete="new-password"
          />

          <button type="button" disabled={loading} onClick={prepareCryptoBootstrap}>
            Create vault keys
          </button>
        </section>
      )}

      {bootstrapOptions && !recoveryKitDownloaded && !completedAccount && (
        <section>
          <h2>Save Recovery Kit</h2>

          <p>
            The Recovery Kit contains secrets required to recover access to your encrypted vault.
            Store it securely and separately from your Master Password.
          </p>

          <button type="button" disabled={loading} onClick={saveRecoveryKit}>
            Download Recovery Kit
          </button>
        </section>
      )}

      {bootstrapOptions && recoveryKitDownloaded && !completedAccount && (
        <section>
          <h2>Activate account</h2>

          <p>
            Your Recovery Kit has been saved. The server will receive only encrypted key envelopes
            and KDF metadata.
          </p>

          <button type="button" disabled={loading} onClick={activateAccount}>
            Activate account
          </button>
        </section>
      )}

      {completedAccount && (
        <section>
          <h2>Account ready</h2>

          <p>Your encrypted personal vault has been created successfully.</p>

          <p>
            Account status: <strong>{completedAccount.status}</strong>
          </p>
        </section>
      )}

      {message && <p>{message}</p>}

      {error && <p role="alert">{error}</p>}
    </main>
  );
}
