import { useEffect, useRef, useState } from 'react';

import {
  browserSupportsWebAuthn,
  startRegistration,
  type PublicKeyCredentialCreationOptionsJSON,
} from '@simplewebauthn/browser';

import './App.css';

import {
  createAccountBootstrap,
  type AccountBootstrapResult,
  type UnlockedVault,
} from './lib/cryptoCore';

import {
  getCurrentSession,
  loginWithPasskey,
  logout as logoutSession,
  type AuthenticatedUser,
} from './lib/authApi';
import { ApiError, apiRequest } from './lib/api';
import { bytesToBase64Url, wipeBytes } from './lib/encoding';
import { downloadRecoveryKit, readRecoveryKit, type RecoveryKit } from './lib/recoveryKit';

import { unlockVault } from './lib/vaultUnlock';

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

  const [runtimeState, setRuntimeState] = useState<RuntimeState>('CHECKING_SESSION');

  const [authenticatedUser, setAuthenticatedUser] = useState<AuthenticatedUser | null>(null);

  const [recoveryKitLoaded, setRecoveryKitLoaded] = useState(false);

  const recoveryKitRef = useRef<RecoveryKit | null>(null);

  const recoveryKitFileRef = useRef<HTMLInputElement>(null);

  const unlockMasterPasswordRef = useRef<HTMLInputElement>(null);

  const unlockedVaultRef = useRef<UnlockedVault | null>(null);

  const unlockedVaultIdRef = useRef<string | null>(null);

  type RuntimeState =
    'CHECKING_SESSION' | 'SESSION_UNAVAILABLE' | 'SIGNED_OUT' | 'AUTHENTICATED_LOCKED' | 'UNLOCKED';

  function disposeUnlockedVault() {
    const unlocked = unlockedVaultRef.current;

    if (unlocked) {
      unlocked.clear();
      unlocked.free();

      unlockedVaultRef.current = null;
      unlockedVaultIdRef.current = null;
    }
  }

  useEffect(() => {
    let cancelled = false;

    async function restoreSession() {
      try {
        const session = await getCurrentSession();

        if (cancelled) {
          return;
        }

        setAuthenticatedUser(session.user);

        setRuntimeState('AUTHENTICATED_LOCKED');
      } catch (error) {
        if (cancelled) {
          return;
        }

        if (error instanceof ApiError && error.status === 401) {
          setRuntimeState('SIGNED_OUT');

          return;
        }

        setError(error instanceof Error ? error.message : 'Session could not be restored.');

        setRuntimeState('SESSION_UNAVAILABLE');
      }
    }

    void restoreSession();

    return () => {
      cancelled = true;

      disposeUnlockedVault();

      const bootstrap = bootstrapRef.current;

      if (bootstrap) {
        bootstrap.clear();
        bootstrap.free();

        bootstrapRef.current = null;
      }

      recoveryKitRef.current = null;
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

  async function handlePasskeyLogin() {
    setLoading(true);
    resetMessages();

    try {
      const session = await loginWithPasskey();

      setAuthenticatedUser(session.user);

      setRuntimeState('AUTHENTICATED_LOCKED');

      setMessage('Authentication successful. Your vault is still locked.');
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Authentication failed.');
    } finally {
      setLoading(false);
    }
  }

  async function retrySessionRestore() {
    setLoading(true);
    resetMessages();

    try {
      const session = await getCurrentSession();

      setAuthenticatedUser(session.user);

      setRuntimeState('AUTHENTICATED_LOCKED');
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        setAuthenticatedUser(null);

        setRuntimeState('SIGNED_OUT');

        return;
      }

      setError(error instanceof Error ? error.message : 'Session could not be restored.');
    } finally {
      setLoading(false);
    }
  }

  async function handleRecoveryKitFile(file: File | undefined) {
    resetMessages();

    if (!file) {
      discardRecoveryKit();
      return;
    }

    if (!authenticatedUser) {
      setError('Authentication is required.');

      return;
    }

    try {
      const recoveryKit = await readRecoveryKit(file);

      if (
        recoveryKit.account.email.trim().toLowerCase() !==
        authenticatedUser.email.trim().toLowerCase()
      ) {
        throw new Error('Recovery Kit belongs to a different account.');
      }

      recoveryKitRef.current = recoveryKit;

      setRecoveryKitLoaded(true);

      setMessage('Recovery Kit loaded locally. It has not been uploaded to the server.');
    } catch (error) {
      discardRecoveryKit();

      setError(error instanceof Error ? error.message : 'Recovery Kit could not be loaded.');
    }
  }

  async function handleUnlockVault() {
    const user = authenticatedUser;

    const recoveryKit = recoveryKitRef.current;

    const masterPassword = unlockMasterPasswordRef.current?.value ?? '';

    resetMessages();

    if (!user || !recoveryKit) {
      setError('Recovery Kit is required.');

      return;
    }

    if (!masterPassword) {
      setError('Master Password is required.');

      return;
    }

    setLoading(true);

    try {
      const unlocked = await unlockVault({
        masterPassword,
        recoveryKit,
        authenticatedEmail: user.email,
      });

      disposeUnlockedVault();

      unlockedVaultRef.current = unlocked;
      unlockedVaultIdRef.current = recoveryKit.account.vaultId;
      /*
       * Drop the Recovery Kit reference after
       * successful unlock. It is no longer
       * needed in memory.
       */
      discardRecoveryKit();

      setRuntimeState('UNLOCKED');

      setMessage('Vault unlocked locally.');
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        disposeUnlockedVault();
        discardRecoveryKit();

        setAuthenticatedUser(null);

        setRuntimeState('SIGNED_OUT');

        setError('Your session has expired. Authenticate again.');

        return;
      }

      setError(error instanceof Error ? error.message : 'Vault could not be unlocked.');
    } finally {
      if (unlockMasterPasswordRef.current) {
        unlockMasterPasswordRef.current.value = '';
      }

      setLoading(false);
    }
  }

  function handleLockVault() {
    disposeUnlockedVault();
    discardRecoveryKit();

    setRuntimeState('AUTHENTICATED_LOCKED');

    setMessage('Vault locked.');
    setError('');
  }

  async function handleLogout() {
    /*
     * Local keys are destroyed immediately,
     * even if the network request fails.
     */
    disposeUnlockedVault();
    discardRecoveryKit();

    setRuntimeState('AUTHENTICATED_LOCKED');

    setLoading(true);
    resetMessages();

    try {
      await logoutSession();

      setAuthenticatedUser(null);

      setRuntimeState('SIGNED_OUT');

      setMessage('Signed out successfully.');
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        setAuthenticatedUser(null);

        setRuntimeState('SIGNED_OUT');

        return;
      }

      setError('The vault was locked locally, but the server session could not be revoked.');
    } finally {
      setLoading(false);
    }
  }

  function finishOnboarding() {
    const bootstrap = bootstrapRef.current;

    if (bootstrap) {
      bootstrap.clear();
      bootstrap.free();

      bootstrapRef.current = null;
    }

    setRegistrationId(null);
    setVerificationToken('');
    setRegistrationToken(null);
    setBootstrapToken(null);
    setBootstrapOptions(null);

    setRecoveryKitDownloaded(false);

    setCompletedAccount(null);

    setEmail('');

    setMessage('Account created. Sign in with your passkey.');
  }

  function discardRecoveryKit() {
    recoveryKitRef.current = null;
    setRecoveryKitLoaded(false);

    if (recoveryKitFileRef.current) {
      recoveryKitFileRef.current.value = '';
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

      {runtimeState === 'CHECKING_SESSION' && (
        <section>
          <h2>Checking session</h2>
          <p>Restoring your authenticated session…</p>
        </section>
      )}

      {runtimeState === 'SESSION_UNAVAILABLE' && (
        <section>
          <h2>Session unavailable</h2>

          <p>The application could not verify your session.</p>

          <button type="button" disabled={loading} onClick={retrySessionRestore}>
            Retry
          </button>
        </section>
      )}

      {runtimeState === 'AUTHENTICATED_LOCKED' && authenticatedUser && (
        <section>
          <h2>Vault locked</h2>

          <p>
            Signed in as <strong>{authenticatedUser.email}</strong>
          </p>

          <p>Your identity is authenticated, but your vault keys are not loaded.</p>

          <label>
            Recovery Kit
            <input
              ref={recoveryKitFileRef}
              type="file"
              accept=".json,application/json"
              onChange={(event) => {
                void handleRecoveryKitFile(event.target.files?.[0]);
              }}
            />
          </label>

          {recoveryKitLoaded && (
            <>
              <input
                ref={unlockMasterPasswordRef}
                type="password"
                placeholder="Master Password"
                autoComplete="current-password"
              />

              <button type="button" disabled={loading} onClick={handleUnlockVault}>
                Unlock vault
              </button>
            </>
          )}

          <button type="button" disabled={loading} onClick={handleLogout}>
            Sign out
          </button>
        </section>
      )}

      {runtimeState === 'UNLOCKED' && authenticatedUser && (
        <section>
          <h2>Vault unlocked</h2>

          <p>
            Signed in as <strong>{authenticatedUser.email}</strong>
          </p>

          <p>Your vault keys are currently available only inside the local WASM crypto runtime.</p>

          <button type="button" onClick={handleLockVault}>
            Lock vault
          </button>

          <button type="button" disabled={loading} onClick={handleLogout}>
            Sign out
          </button>
        </section>
      )}

      {runtimeState === 'SIGNED_OUT' && (
        <>
          {!registrationId && !completedAccount && (
            <>
              <section>
                <h2>Sign in</h2>

                <p>Authenticate with your passkey.</p>

                <button
                  type="button"
                  disabled={loading || !webAuthnSupported}
                  onClick={handlePasskeyLogin}
                >
                  Sign in with passkey
                </button>
              </section>

              <section>
                <h2>Create account</h2>

                <input
                  type="email"
                  value={email}
                  placeholder="you@example.com"
                  autoComplete="email"
                  onChange={(event) => setEmail(event.target.value)}
                />

                <button
                  type="button"
                  disabled={loading || !email}
                  onClick={startAccountRegistration}
                >
                  Start registration
                </button>
              </section>
            </>
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

              <button
                type="button"
                disabled={loading || !webAuthnSupported}
                onClick={registerPasskey}
              >
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

              <p>Store it securely and separately from your Master Password.</p>

              <button type="button" disabled={loading} onClick={saveRecoveryKit}>
                Download Recovery Kit
              </button>
            </section>
          )}

          {bootstrapOptions && recoveryKitDownloaded && !completedAccount && (
            <section>
              <h2>Activate account</h2>

              <button type="button" disabled={loading} onClick={activateAccount}>
                Activate account
              </button>
            </section>
          )}

          {completedAccount && (
            <section>
              <h2>Account ready</h2>

              <p>Your encrypted personal vault has been created.</p>

              <button type="button" onClick={finishOnboarding}>
                Continue to sign in
              </button>
            </section>
          )}
        </>
      )}

      {!webAuthnSupported && <p role="alert">This browser does not support WebAuthn.</p>}

      {message && <p>{message}</p>}

      {error && <p role="alert">{error}</p>}
    </main>
  );
}
