import { useEffect, useRef, useState, useCallback } from 'react';

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

import type { LoginItemPayload } from './lib/cryptoCore';

import type { EncryptedVaultItem } from './lib/vaultItemApi';

import {
  createLoginVaultItem,
  deleteVaultItem,
  listVaultItemsIncludingDeleted,
  loadAndDecryptLoginItem,
  restoreVaultItem,
  updateLoginVaultItem,
  applyVaultItemSyncChanges,
  syncVaultItemChanges,
  type VaultItemCollections,
} from './lib/vaultItems';

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

  const [vaultItems, setVaultItems] = useState<EncryptedVaultItem[]>([]);

  const [selectedLogin, setSelectedLogin] = useState<LoginItemPayload | null>(null);

  const [selectedItemId, setSelectedItemId] = useState<string | null>(null);

  const loginNameRef = useRef<HTMLInputElement>(null);

  const loginUsernameRef = useRef<HTMLInputElement>(null);

  const loginPasswordRef = useRef<HTMLInputElement>(null);

  const loginUrlRef = useRef<HTMLInputElement>(null);

  const loginNotesRef = useRef<HTMLTextAreaElement>(null);

  const [editingLogin, setEditingLogin] = useState(false);

  const editNameRef = useRef<HTMLInputElement>(null);

  const editUsernameRef = useRef<HTMLInputElement>(null);

  const editPasswordRef = useRef<HTMLInputElement>(null);

  const editUrlRef = useRef<HTMLInputElement>(null);

  const editNotesRef = useRef<HTMLTextAreaElement>(null);

  const [deletedVaultItems, setDeletedVaultItems] = useState<EncryptedVaultItem[]>([]);

  const vaultSyncCursorRef = useRef<string | null>(null);

  const vaultSyncInFlightRef = useRef(false);

  const vaultItemsRef = useRef<EncryptedVaultItem[]>([]);

  const deletedVaultItemsRef = useRef<EncryptedVaultItem[]>([]);

  const selectedItemIdRef = useRef<string | null>(null);

  type RuntimeState =
    'CHECKING_SESSION' | 'SESSION_UNAVAILABLE' | 'SIGNED_OUT' | 'AUTHENTICATED_LOCKED' | 'UNLOCKED';

  const syncVaultItemsNow = useCallback(
    async (showStatus: boolean) => {
      const vaultId = unlockedVaultIdRef.current;

      if (runtimeState !== 'UNLOCKED' || !vaultId || vaultSyncInFlightRef.current) {
        return;
      }

      vaultSyncInFlightRef.current = true;

      try {
        let cursor = vaultSyncCursorRef.current ?? undefined;

        let collections: VaultItemCollections = {
          activeItems: vaultItemsRef.current,

          deletedItems: deletedVaultItemsRef.current,
        };

        let receivedChanges = 0;

        while (true) {
          const result = await syncVaultItemChanges(vaultId, cursor);

          receivedChanges += result.changes.length;

          const currentSelectedItemId = selectedItemIdRef.current;

          const selectedChanged =
            currentSelectedItemId !== null &&
            result.changes.some(
              (change) =>
                change.itemId === currentSelectedItemId &&
                (change.kind === 'UPDATED' ||
                  change.kind === 'DELETED' ||
                  change.kind === 'RESTORED'),
            );

          if (selectedChanged) {
            selectedItemIdRef.current = null;

            setEditingLogin(false);
            setSelectedLogin(null);
            setSelectedItemId(null);
          }

          collections = applyVaultItemSyncChanges(collections, result.changes);

          cursor = result.sync.nextCursor;

          if (!result.sync.hasMore) {
            break;
          }
        }

        vaultItemsRef.current = collections.activeItems;

        deletedVaultItemsRef.current = collections.deletedItems;

        setVaultItems(collections.activeItems);

        setDeletedVaultItems(collections.deletedItems);

        vaultSyncCursorRef.current = cursor ?? null;

        if (showStatus) {
          setMessage(
            receivedChanges === 0
              ? 'Vault is already synchronized.'
              : `Applied ${receivedChanges} vault change${receivedChanges === 1 ? '' : 's'}.`,
          );
        }
      } finally {
        vaultSyncInFlightRef.current = false;
      }
    },
    [runtimeState],
  );

  const clearVaultUiState = useCallback(() => {
    vaultItemsRef.current = [];
    deletedVaultItemsRef.current = [];
    selectedItemIdRef.current = null;
    vaultSyncCursorRef.current = null;
    vaultSyncInFlightRef.current = false;

    setVaultItems([]);
    setSelectedLogin(null);
    setSelectedItemId(null);
    setEditingLogin(false);
    setDeletedVaultItems([]);

    if (loginNameRef.current) {
      loginNameRef.current.value = '';
    }

    if (loginUsernameRef.current) {
      loginUsernameRef.current.value = '';
    }

    if (loginPasswordRef.current) {
      loginPasswordRef.current.value = '';
    }

    if (loginUrlRef.current) {
      loginUrlRef.current.value = '';
    }

    if (loginNotesRef.current) {
      loginNotesRef.current.value = '';
    }

    if (editNameRef.current) {
      editNameRef.current.value = '';
    }

    if (editUsernameRef.current) {
      editUsernameRef.current.value = '';
    }

    if (editPasswordRef.current) {
      editPasswordRef.current.value = '';
    }

    if (editUrlRef.current) {
      editUrlRef.current.value = '';
    }

    if (editNotesRef.current) {
      editNotesRef.current.value = '';
    }
  }, []);

  const disposeUnlockedVault = useCallback(() => {
    const unlocked = unlockedVaultRef.current;

    if (unlocked) {
      unlocked.clear();
      unlocked.free();

      unlockedVaultRef.current = null;

      unlockedVaultIdRef.current = null;
    }
  }, []);

  const handleBackgroundSyncError = useCallback(
    async (error: unknown) => {
      if (error instanceof ApiError && error.status === 401) {
        disposeUnlockedVault();
        clearVaultUiState();

        setAuthenticatedUser(null);

        setRuntimeState('SIGNED_OUT');

        setError('Your session has expired. Authenticate again.');

        return;
      }

      console.error('Vault background sync failed.', error);
    },
    [clearVaultUiState, disposeUnlockedVault],
  );

  async function handleDeleteLoginItem(itemId: string) {
    const vaultId = unlockedVaultIdRef.current;

    if (!vaultId) {
      setError('Vault is locked.');

      return;
    }

    const item = vaultItems.find((entry) => entry.id === itemId);

    if (!item) {
      setError('Vault item metadata is unavailable.');

      return;
    }

    const confirmed = window.confirm(
      'Delete this login? The encrypted history will be retained for recovery.',
    );

    if (!confirmed) {
      return;
    }

    resetMessages();

    setLoading(true);

    try {
      await deleteVaultItem(vaultId, itemId, item.revisionNumber);

      /*

       * Drop decrypted plaintext immediately

       * when the selected item is deleted.

       */

      if (selectedItemId === itemId) {
        selectedItemIdRef.current = null;
        setEditingLogin(false);
        setSelectedLogin(null);
        setSelectedItemId(null);
      }

      await refreshVaultItems();

      setMessage('Login deleted.');
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        disposeUnlockedVault();

        clearVaultUiState();

        setAuthenticatedUser(null);

        setRuntimeState('SIGNED_OUT');

        setError('Your session has expired. Authenticate again.');

        return;
      }

      if (error instanceof ApiError && error.code === 'ITEM_REVISION_CONFLICT') {
        /*

         * Another client changed the item.

         * Do not allow this stale tab to keep

         * operating on the old plaintext.

         */

        if (selectedItemId === itemId) {
          selectedItemIdRef.current = null;
          setEditingLogin(false);
          setSelectedLogin(null);
          setSelectedItemId(null);
        }

        try {
          await refreshVaultItems();
        } catch {
          vaultItemsRef.current = [];
          deletedVaultItemsRef.current = [];
          setVaultItems([]);
          setDeletedVaultItems([]);
        }

        setError(
          'This item changed in another client. Review the latest revision before deleting it.',
        );

        return;
      }

      if (error instanceof ApiError && error.code === 'ITEM_NOT_FOUND') {
        if (selectedItemId === itemId) {
          selectedItemIdRef.current = null;
          setEditingLogin(false);
          setSelectedLogin(null);
          setSelectedItemId(null);
        }

        await refreshVaultItems();

        setError('This item no longer exists in the active vault.');

        return;
      }

      setError(error instanceof Error ? error.message : 'Login could not be deleted.');
    } finally {
      setLoading(false);
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
  }, [disposeUnlockedVault]);

  useEffect(() => {
    vaultItemsRef.current = vaultItems;
  }, [vaultItems]);

  useEffect(() => {
    deletedVaultItemsRef.current = deletedVaultItems;
  }, [deletedVaultItems]);

  useEffect(() => {
    selectedItemIdRef.current = selectedItemId;
  }, [selectedItemId]);

  function resetMessages() {
    setError('');

    setMessage('');
  }

  async function bootstrapVaultSync(vaultId: string): Promise<void> {
    /*
     * First get the current server state.
     * This also guarantees that legacy
     * deleted items are represented locally.
     */
    const allItems = await listVaultItemsIncludingDeleted(vaultId);

    let collections: VaultItemCollections = {
      activeItems: allItems.filter((item) => item.deletedAt === null),
      deletedItems: allItems.filter((item) => item.deletedAt !== null),
    };

    let cursor: string | undefined;

    /*
     * Replay the append-only change feed up
     * to its current head.
     *
     * This catches mutations that happened
     * while the full snapshot was loading.
     */
    while (true) {
      const result = await syncVaultItemChanges(vaultId, cursor);

      collections = applyVaultItemSyncChanges(collections, result.changes);
      cursor = result.sync.nextCursor;

      if (!result.sync.hasMore) {
        break;
      }
    }

    vaultItemsRef.current = collections.activeItems;
    deletedVaultItemsRef.current = collections.deletedItems;

    setVaultItems(collections.activeItems);
    setDeletedVaultItems(collections.deletedItems);

    vaultSyncCursorRef.current = cursor ?? null;
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

  useEffect(() => {
    if (runtimeState !== 'UNLOCKED') {
      return;
    }

    function handleVisibilityChange() {
      if (document.visibilityState !== 'visible') {
        return;
      }

      void syncVaultItemsNow(false).catch(handleBackgroundSyncError);
    }

    function handleWindowFocus() {
      void syncVaultItemsNow(false).catch(handleBackgroundSyncError);
    }

    document.addEventListener('visibilitychange', handleVisibilityChange);

    window.addEventListener('focus', handleWindowFocus);

    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);

      window.removeEventListener('focus', handleWindowFocus);
    };
  }, [runtimeState, syncVaultItemsNow, handleBackgroundSyncError]);

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

  async function handleSyncVaultItems() {
    resetMessages();

    setLoading(true);

    try {
      await syncVaultItemsNow(true);
    } catch (error) {
      const vaultId = unlockedVaultIdRef.current;

      if (error instanceof ApiError && error.status === 401) {
        disposeUnlockedVault();

        clearVaultUiState();

        setAuthenticatedUser(null);

        setRuntimeState('SIGNED_OUT');

        setError('Your session has expired. Authenticate again.');

        return;
      }

      if (vaultId) {
        try {
          await bootstrapVaultSync(vaultId);

          setError('Vault sync state was rebuilt from the server.');

          return;
        } catch {
          // Fall through to original error.
        }
      }

      setError(error instanceof Error ? error.message : 'Vault synchronization failed.');
    } finally {
      setLoading(false);
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

      try {
        await bootstrapVaultSync(recoveryKit.account.vaultId);
      } catch {
        vaultItemsRef.current = [];
        deletedVaultItemsRef.current = [];
        vaultSyncCursorRef.current = null;

        setVaultItems([]);
        setDeletedVaultItems([]);
        setError('Vault unlocked, but items could not be loaded.');
      }

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

    clearVaultUiState();

    setRuntimeState('AUTHENTICATED_LOCKED');

    setMessage('Vault locked.');

    setError('');
  }

  async function handleCreateLoginItem() {
    const vault = unlockedVaultRef.current;

    const vaultId = unlockedVaultIdRef.current;

    if (!vault || !vaultId) {
      setError('Vault is locked.');

      return;
    }

    const name = loginNameRef.current?.value.trim() ?? '';

    const username = loginUsernameRef.current?.value ?? '';

    const password = loginPasswordRef.current?.value ?? '';

    const url = loginUrlRef.current?.value.trim() ?? '';

    const notes = loginNotesRef.current?.value ?? '';

    resetMessages();

    if (!name) {
      setError('Login name is required.');

      return;
    }

    setLoading(true);

    try {
      await createLoginVaultItem(vault, vaultId, {
        name,

        username,

        password,

        urls: url.length > 0 ? [url] : [],

        notes,
      });

      /*

       * Remove plaintext from the form as

       * soon as persistence succeeds.

       */

      if (loginNameRef.current) {
        loginNameRef.current.value = '';
      }

      if (loginUsernameRef.current) {
        loginUsernameRef.current.value = '';
      }

      if (loginPasswordRef.current) {
        loginPasswordRef.current.value = '';
      }

      if (loginUrlRef.current) {
        loginUrlRef.current.value = '';
      }

      if (loginNotesRef.current) {
        loginNotesRef.current.value = '';
      }

      setSelectedLogin(null);
      selectedItemIdRef.current = null;
      setSelectedItemId(null);

      await refreshVaultItems();

      setMessage('Login encrypted and saved.');
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        disposeUnlockedVault();

        clearVaultUiState();

        setAuthenticatedUser(null);

        setRuntimeState('SIGNED_OUT');

        setError('Your session has expired. Authenticate again.');

        return;
      }

      setError(error instanceof Error ? error.message : 'Login could not be saved.');
    } finally {
      /*

       * Always remove the password from

       * the DOM after an attempt.

       */

      if (loginPasswordRef.current) {
        loginPasswordRef.current.value = '';
      }

      setLoading(false);
    }
  }

  async function handleViewLoginItem(itemId: string) {
    const vault = unlockedVaultRef.current;

    const vaultId = unlockedVaultIdRef.current;

    if (!vault || !vaultId) {
      setError('Vault is locked.');

      return;
    }

    setLoading(true);

    resetMessages();

    /*

     * Drop any previously decrypted item

     * before loading another one.

     */

    setSelectedLogin(null);
    selectedItemIdRef.current = null;
    setSelectedItemId(null);
    setEditingLogin(false);

    try {
      const login = await loadAndDecryptLoginItem(vault, vaultId, itemId);

      setSelectedLogin(login);
      selectedItemIdRef.current = itemId;
      setSelectedItemId(itemId);
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        disposeUnlockedVault();

        clearVaultUiState();

        setAuthenticatedUser(null);

        setRuntimeState('SIGNED_OUT');

        setError('Your session has expired. Authenticate again.');

        return;
      }

      setError(error instanceof Error ? error.message : 'Login could not be decrypted.');
    } finally {
      setLoading(false);
    }
  }

  function handleCloseLoginItem() {
    selectedItemIdRef.current = null;
    setEditingLogin(false);
    setSelectedLogin(null);
    setSelectedItemId(null);
  }

  function handleStartEditingLogin() {
    if (!selectedLogin || !selectedItemId) {
      return;
    }

    setEditingLogin(true);

    resetMessages();
  }

  function handleCancelEditingLogin() {
    setEditingLogin(false);

    if (editPasswordRef.current) {
      editPasswordRef.current.value = '';
    }
  }

  async function handleUpdateLoginItem() {
    const vault = unlockedVaultRef.current;

    const vaultId = unlockedVaultIdRef.current;

    const itemId = selectedItemId;

    if (!vault || !vaultId || !itemId || !selectedLogin) {
      setError('No vault item is selected.');

      return;
    }

    /*

     * The revision displayed in this tab is

     * the revision this edit is based on.

     *

     * If another tab/client already changed

     * it, the backend will return 409.

     */

    const itemMetadata = vaultItems.find((item) => item.id === itemId);

    if (!itemMetadata) {
      setError('Vault item metadata is unavailable.');

      return;
    }

    const name = editNameRef.current?.value.trim() ?? '';

    const username = editUsernameRef.current?.value ?? '';

    const password = editPasswordRef.current?.value ?? '';

    const url = editUrlRef.current?.value.trim() ?? '';

    const notes = editNotesRef.current?.value ?? '';

    resetMessages();

    if (!name) {
      setError('Login name is required.');

      return;
    }

    setLoading(true);

    try {
      const updated = await updateLoginVaultItem(
        vault,

        vaultId,

        itemId,

        itemMetadata.revisionNumber,

        {
          name,

          username,

          password,

          urls: url.length > 0 ? [url] : [],

          notes,
        },
      );

      /*

       * Read the newly persisted revision

       * back from the server and decrypt it,

       * rather than trusting only our local

       * draft.

       */

      await refreshVaultItems();

      const refreshedLogin = await loadAndDecryptLoginItem(vault, vaultId, itemId);

      setSelectedLogin(refreshedLogin);

      setEditingLogin(false);

      setMessage(`Login updated to revision ${updated.revisionNumber}.`);
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        disposeUnlockedVault();

        clearVaultUiState();

        setAuthenticatedUser(null);

        setRuntimeState('SIGNED_OUT');

        setError('Your session has expired. Authenticate again.');

        return;
      }

      if (error instanceof ApiError && error.code === 'ITEM_REVISION_CONFLICT') {
        /*

         * Do not let the stale editor remain

         * open after a concurrency conflict.

         */

        selectedItemIdRef.current = null;
        setEditingLogin(false);
        setSelectedLogin(null);
        setSelectedItemId(null);

        try {
          await refreshVaultItems();
        } catch {
          vaultItemsRef.current = [];
          deletedVaultItemsRef.current = [];
          setVaultItems([]);
          setDeletedVaultItems([]);
        }

        setError(
          'This item changed in another client. Open it again to review the latest revision.',
        );

        return;
      }

      setError(error instanceof Error ? error.message : 'Login could not be updated.');
    } finally {
      /*

       * Password plaintext should not remain

       * in an edit field after a save attempt.

       */

      if (editPasswordRef.current) {
        editPasswordRef.current.value = '';
      }

      setLoading(false);
    }
  }

  async function handleRestoreLoginItem(itemId: string) {
    const vaultId = unlockedVaultIdRef.current;

    if (!vaultId) {
      setError('Vault is locked.');

      return;
    }

    const item = deletedVaultItems.find((entry) => entry.id === itemId);

    if (!item) {
      setError('Deleted item metadata is unavailable.');

      return;
    }

    resetMessages();

    setLoading(true);

    try {
      await restoreVaultItem(vaultId, itemId, item.revisionNumber);

      await refreshVaultItems();

      setMessage('Login restored.');
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        disposeUnlockedVault();

        clearVaultUiState();

        setAuthenticatedUser(null);

        setRuntimeState('SIGNED_OUT');

        setError('Your session has expired. Authenticate again.');

        return;
      }

      if (error instanceof ApiError && error.code === 'ITEM_REVISION_CONFLICT') {
        await refreshVaultItems();

        setError('This item changed in another client. Refresh and try again.');

        return;
      }

      if (error instanceof ApiError && error.code === 'ITEM_NOT_FOUND') {
        await refreshVaultItems();

        setError('This deleted item no longer exists.');

        return;
      }

      setError(error instanceof Error ? error.message : 'Login could not be restored.');
    } finally {
      setLoading(false);
    }
  }

  async function handleLogout() {
    /*

     * Local keys are destroyed immediately,

     * even if the network request fails.

     */

    disposeUnlockedVault();

    discardRecoveryKit();

    clearVaultUiState();

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

  async function refreshVaultItems() {
    const vault = unlockedVaultRef.current;
    const vaultId = unlockedVaultIdRef.current;

    if (!vault || !vaultId) {
      return;
    }

    try {
      const allItems = await listVaultItemsIncludingDeleted(vaultId);

      const activeItems = allItems.filter((item) => item.deletedAt === null);
      const deletedItems = allItems.filter((item) => item.deletedAt !== null);

      vaultItemsRef.current = activeItems;
      deletedVaultItemsRef.current = deletedItems;

      setVaultItems(activeItems);
      setDeletedVaultItems(deletedItems);
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        disposeUnlockedVault();
        clearVaultUiState();

        setAuthenticatedUser(null);
        setRuntimeState('SIGNED_OUT');
        setError('Your session has expired. Authenticate again.');

        return;
      }

      setError(error instanceof Error ? error.message : 'Vault items could not be loaded.');
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

          <p>Vault keys are available only inside the local WASM runtime.</p>

          <hr />

          <h3>New login</h3>

          <div>
            <label>
              Name
              <input ref={loginNameRef} type="text" autoComplete="off" placeholder="GitHub" />
            </label>
          </div>

          <div>
            <label>
              Username
              <input
                ref={loginUsernameRef}

                type="text"

                autoComplete="off"

                placeholder="you@example.com"
              />
            </label>
          </div>

          <div>
            <label>
              Password
              <input
                ref={loginPasswordRef}

                type="password"

                autoComplete="off"

                placeholder="Password"
              />
            </label>
          </div>

          <div>
            <label>
              URL
              <input
                ref={loginUrlRef}

                type="url"

                autoComplete="off"

                placeholder="https://example.com"
              />
            </label>
          </div>

          <div>
            <label>
              Notes
              <textarea ref={loginNotesRef} placeholder="Optional notes" />
            </label>
          </div>

          <button type="button" disabled={loading} onClick={handleCreateLoginItem}>
            Save login
          </button>

          <hr />

          <h3>Vault items</h3>

          <button
            type="button"

            disabled={loading}

            onClick={() => {
              void refreshVaultItems();
            }}
          >
            Refresh
          </button>

          {vaultItems.length === 0 ? (
            <p>No saved items yet.</p>
          ) : (
            <ul>
              {vaultItems.map((item) => (
                <li key={item.id}>
                  <code>{item.id}</code>
                  {' — revision '}
                  {item.revisionNumber}{' '}
                  <button
                    type="button"

                    disabled={loading}

                    onClick={() => {
                      void handleViewLoginItem(item.id);
                    }}
                  >
                    View
                  </button>{' '}
                  <button
                    type="button"

                    disabled={loading}

                    onClick={() => {
                      void handleDeleteLoginItem(item.id);
                    }}
                  >
                    Delete
                  </button>
                </li>
              ))}
            </ul>
          )}

          <hr />

          <h3>Deleted items</h3>

          {deletedVaultItems.length === 0 ? (
            <p>No deleted items.</p>
          ) : (
            <ul>
              {deletedVaultItems.map((item) => (
                <li key={item.id}>
                  <code>{item.id}</code>
                  {' — revision '}
                  {item.revisionNumber}
                  {' — deleted '}
                  {item.deletedAt ? new Date(item.deletedAt).toLocaleString() : ''}{' '}
                  <button
                    type="button"

                    disabled={loading}

                    onClick={() => {
                      void handleRestoreLoginItem(item.id);
                    }}
                  >
                    Restore
                  </button>
                </li>
              ))}
            </ul>
          )}

          {selectedLogin && selectedItemId && (
            <>
              <hr />

              <h3>Decrypted login</h3>

              <p>
                <strong>Item ID:</strong> <code>{selectedItemId}</code>
              </p>

              {!editingLogin ? (
                <>
                  <p>
                    <strong>Name:</strong> {selectedLogin.name}
                  </p>

                  <p>
                    <strong>Username:</strong> {selectedLogin.username}
                  </p>

                  <p>
                    <strong>Password:</strong> <code>{selectedLogin.password}</code>
                  </p>

                  <p>
                    <strong>URLs:</strong>
                  </p>

                  {selectedLogin.urls.length === 0 ? (
                    <p>None</p>
                  ) : (
                    <ul>
                      {selectedLogin.urls.map((url) => (
                        <li key={url}>{url}</li>
                      ))}
                    </ul>
                  )}

                  <p>
                    <strong>Notes:</strong> {selectedLogin.notes}
                  </p>

                  <button type="button" disabled={loading} onClick={handleStartEditingLogin}>
                    Edit
                  </button>

                  <button
                    type="button"

                    disabled={loading}

                    onClick={() => {
                      void handleDeleteLoginItem(selectedItemId);
                    }}
                  >
                    Delete
                  </button>

                  <button type="button" onClick={handleCloseLoginItem}>
                    Close
                  </button>
                </>
              ) : (
                <>
                  <h4>Edit login</h4>

                  <div>
                    <label>
                      Name
                      <input
                        ref={editNameRef}

                        type="text"

                        autoComplete="off"

                        defaultValue={selectedLogin.name}
                      />
                    </label>
                  </div>

                  <div>
                    <label>
                      Username
                      <input
                        ref={editUsernameRef}

                        type="text"

                        autoComplete="off"

                        defaultValue={selectedLogin.username}
                      />
                    </label>
                  </div>

                  <div>
                    <label>
                      Password
                      <input
                        ref={editPasswordRef}

                        type="password"

                        autoComplete="off"

                        defaultValue={selectedLogin.password}
                      />
                    </label>
                  </div>

                  <div>
                    <label>
                      URL
                      <input
                        ref={editUrlRef}

                        type="url"

                        autoComplete="off"

                        defaultValue={selectedLogin.urls[0] ?? ''}
                      />
                    </label>
                  </div>

                  <div>
                    <label>
                      Notes
                      <textarea ref={editNotesRef} defaultValue={selectedLogin.notes} />
                    </label>
                  </div>

                  <button type="button" disabled={loading} onClick={handleUpdateLoginItem}>
                    Save changes
                  </button>

                  <button type="button" disabled={loading} onClick={handleCancelEditingLogin}>
                    Cancel
                  </button>
                </>
              )}
            </>
          )}

          <hr />

          <button
            type="button"

            disabled={loading}

            onClick={() => {
              void handleSyncVaultItems();
            }}
          >
            Sync changes
          </button>

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
