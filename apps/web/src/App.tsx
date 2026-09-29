import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { useLocation, useNavigate } from 'react-router-dom';

import { resolveRuntimeRedirect, type RuntimeState } from './lib/runtimeRouting';

import { getVaultItemIdFromPath } from './lib/vaultRouting';

import { generatePassword } from './lib/passwordGenerator';

import { routes } from './lib/routes';

import { evaluatePasswordStrength, type PasswordStrengthAssessment } from './lib/passwordStrength';

import { createVaultSearchEntry, type VaultSearchEntry } from './lib/vaultSearch';

import { createVaultListView } from './lib/vaultList';

import {
  browserSupportsWebAuthn,
  startRegistration,
  type PublicKeyCredentialCreationOptionsJSON,
} from '@simplewebauthn/browser';

import {
  listSessions,
  revokeOtherSessions,
  revokeSession,
  type ManagedSession,
} from './lib/sessionApi';

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
import { recoverVaultMasterPassword } from './lib/vaultRecovery';
import { changeVaultMasterPassword } from './lib/vaultMasterPassword';

import type { LoginItemPayload } from './lib/cryptoCore';

import type { EncryptedVaultItem } from './lib/vaultItemApi';

import {
  createLoginVaultItem,
  deleteVaultItem,
  decryptStoredLoginItem,
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

interface PasswordStrengthFeedbackProps {
  assessment: PasswordStrengthAssessment | null;
  loading: boolean;
}

function PasswordStrengthFeedback({ assessment, loading }: PasswordStrengthFeedbackProps) {
  if (loading) {
    return <p aria-live="polite">Evaluating password strength…</p>;
  }

  if (!assessment || assessment.status === 'empty') {
    return null;
  }

  return (
    <div aria-live="polite">
      <p>
        <strong>Password strength:</strong> {assessment.label}
      </p>

      {assessment.status === 'estimated' && assessment.score !== null && (
        <meter
          min={0}
          max={4}
          value={assessment.score}
          aria-label={`Password strength: ${assessment.label}`}
        >
          {assessment.score} out of 4
        </meter>
      )}

      {assessment.warning && <p>{assessment.warning}</p>}

      {assessment.suggestions.length > 0 && (
        <ul>
          {assessment.suggestions.map((suggestion) => (
            <li key={suggestion}>{suggestion}</li>
          ))}
        </ul>
      )}
    </div>
  );
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

  const recoveryKitRouteRef = useRef<string | null>(null);

  const recoveryKitFileRef = useRef<HTMLInputElement>(null);

  const unlockMasterPasswordRef = useRef<HTMLInputElement>(null);

  const changeCurrentMasterPasswordRef = useRef<HTMLInputElement>(null);

  const changeNewMasterPasswordRef = useRef<HTMLInputElement>(null);

  const changeConfirmMasterPasswordRef = useRef<HTMLInputElement>(null);

  const recoveryNewMasterPasswordRef = useRef<HTMLInputElement>(null);

  const recoveryConfirmMasterPasswordRef = useRef<HTMLInputElement>(null);

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

  const [newLoginPasswordStrength, setNewLoginPasswordStrength] =
    useState<PasswordStrengthAssessment | null>(null);

  const [newLoginPasswordStrengthLoading, setNewLoginPasswordStrengthLoading] = useState(false);

  const [editLoginPasswordStrength, setEditLoginPasswordStrength] =
    useState<PasswordStrengthAssessment | null>(null);

  const [editLoginPasswordStrengthLoading, setEditLoginPasswordStrengthLoading] = useState(false);

  const newLoginPasswordStrengthTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const editLoginPasswordStrengthTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const newLoginPasswordStrengthRequestRef = useRef(0);

  const editLoginPasswordStrengthRequestRef = useRef(0);

  const [newLoginPasswordVisible, setNewLoginPasswordVisible] = useState(false);

  const [selectedLoginPasswordVisible, setSelectedLoginPasswordVisible] = useState(false);

  const [editLoginPasswordVisible, setEditLoginPasswordVisible] = useState(false);

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

  const [managedSessions, setManagedSessions] = useState<ManagedSession[]>([]);

  const [securitySessionsLoading, setSecuritySessionsLoading] = useState(false);

  const securitySessionsRequestRef = useRef(0);

  const [vaultSearchEntries, setVaultSearchEntries] = useState<VaultSearchEntry[]>([]);

  const [vaultSearchQuery, setVaultSearchQuery] = useState('');

  const [vaultSearchIndexing, setVaultSearchIndexing] = useState(false);

  const [vaultSearchIndexError, setVaultSearchIndexError] = useState('');

  const vaultSearchGenerationRef = useRef(0);

  const vaultSearchBuildPromiseRef = useRef<Promise<void> | null>(null);

  const location = useLocation();

  const navigate = useNavigate();

  const isLoginRoute = location.pathname === routes.login;

  const isRegisterRoute = location.pathname === routes.register;

  const isVaultRoute = location.pathname === routes.vault;

  const isSecurityRoute = location.pathname === routes.security;

  const isRecoveryRoute = location.pathname === routes.recovery;

  const routedVaultItemId = getVaultItemIdFromPath(location.pathname);

  const isVaultItemRoute = routedVaultItemId !== null;

  const routedItemLoadRef = useRef<string | null>(null);

  const vaultListView = useMemo(
    () => createVaultListView(vaultSearchEntries, vaultSearchQuery),
    [vaultSearchEntries, vaultSearchQuery],
  );

  const rebuildVaultSearchIndex = useCallback(
    async (items: EncryptedVaultItem[]): Promise<void> => {
      const vault = unlockedVaultRef.current;
      const vaultId = unlockedVaultIdRef.current;

      if (!vault || !vaultId) {
        return;
      }

      const generation = vaultSearchGenerationRef.current + 1;

      vaultSearchGenerationRef.current = generation;

      const previousBuild = vaultSearchBuildPromiseRef.current;

      const buildPromise = (async () => {
        if (previousBuild) {
          try {
            await previousBuild;
          } catch {
            // A previous index build must not block a newer rebuild.
          }
        }

        if (
          vaultSearchGenerationRef.current !== generation ||
          unlockedVaultRef.current !== vault ||
          unlockedVaultIdRef.current !== vaultId
        ) {
          return;
        }

        setVaultSearchIndexing(true);
        setVaultSearchIndexError('');

        const entries: VaultSearchEntry[] = [];

        let failedItems = 0;

        for (const item of items) {
          if (
            vaultSearchGenerationRef.current !== generation ||
            unlockedVaultRef.current !== vault ||
            unlockedVaultIdRef.current !== vaultId
          ) {
            return;
          }

          try {
            const login = await decryptStoredLoginItem(vault, vaultId, item);

            if (
              vaultSearchGenerationRef.current !== generation ||
              unlockedVaultRef.current !== vault ||
              unlockedVaultIdRef.current !== vaultId
            ) {
              return;
            }

            entries.push(createVaultSearchEntry(item.id, login));
          } catch {
            failedItems += 1;
          }
        }

        if (
          vaultSearchGenerationRef.current !== generation ||
          unlockedVaultRef.current !== vault ||
          unlockedVaultIdRef.current !== vaultId
        ) {
          return;
        }

        setVaultSearchEntries(entries);

        if (failedItems > 0) {
          setVaultSearchIndexError(
            `${failedItems} vault item${failedItems === 1 ? '' : 's'} could not be indexed locally.`,
          );
        }
      })().finally(() => {
        if (vaultSearchBuildPromiseRef.current === buildPromise) {
          vaultSearchBuildPromiseRef.current = null;

          if (vaultSearchGenerationRef.current === generation) {
            setVaultSearchIndexing(false);
          }
        }
      });

      vaultSearchBuildPromiseRef.current = buildPromise;

      await buildPromise;
    },
    [],
  );

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
            setSelectedLoginPasswordVisible(false);
            setEditLoginPasswordVisible(false);

            setSelectedLogin(null);
            setSelectedItemId(null);

            navigate(routes.vault, {
              replace: true,
            });
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

        if (receivedChanges > 0) {
          await rebuildVaultSearchIndex(collections.activeItems);
        }

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
    [runtimeState, rebuildVaultSearchIndex, navigate],
  );

  const clearNewLoginPasswordStrength = useCallback(() => {
    newLoginPasswordStrengthRequestRef.current += 1;

    if (newLoginPasswordStrengthTimerRef.current) {
      clearTimeout(newLoginPasswordStrengthTimerRef.current);

      newLoginPasswordStrengthTimerRef.current = null;
    }

    setNewLoginPasswordStrength(null);
    setNewLoginPasswordStrengthLoading(false);
  }, []);

  const clearEditLoginPasswordStrength = useCallback(() => {
    editLoginPasswordStrengthRequestRef.current += 1;

    if (editLoginPasswordStrengthTimerRef.current) {
      clearTimeout(editLoginPasswordStrengthTimerRef.current);

      editLoginPasswordStrengthTimerRef.current = null;
    }

    setEditLoginPasswordStrength(null);
    setEditLoginPasswordStrengthLoading(false);
  }, []);

  const scheduleNewLoginPasswordStrength = useCallback(() => {
    const requestId = ++newLoginPasswordStrengthRequestRef.current;

    if (newLoginPasswordStrengthTimerRef.current) {
      clearTimeout(newLoginPasswordStrengthTimerRef.current);
    }

    setNewLoginPasswordStrength(null);
    setNewLoginPasswordStrengthLoading(false);

    newLoginPasswordStrengthTimerRef.current = setTimeout(() => {
      newLoginPasswordStrengthTimerRef.current = null;

      if (newLoginPasswordStrengthRequestRef.current !== requestId) {
        return;
      }

      /*
       * Read plaintext only after the debounce
       * expires. It is never copied into React state.
       */
      const password = loginPasswordRef.current?.value ?? '';

      if (!password) {
        setNewLoginPasswordStrength(null);
        return;
      }

      const context = [
        loginNameRef.current?.value ?? '',
        loginUsernameRef.current?.value ?? '',
        loginUrlRef.current?.value ?? '',
      ];

      setNewLoginPasswordStrengthLoading(true);

      void evaluatePasswordStrength(password, context).then((assessment) => {
        if (newLoginPasswordStrengthRequestRef.current !== requestId) {
          return;
        }

        setNewLoginPasswordStrength(assessment);
        setNewLoginPasswordStrengthLoading(false);
      });
    }, 350);
  }, []);

  const scheduleEditLoginPasswordStrength = useCallback(() => {
    const requestId = ++editLoginPasswordStrengthRequestRef.current;

    if (editLoginPasswordStrengthTimerRef.current) {
      clearTimeout(editLoginPasswordStrengthTimerRef.current);
    }

    editLoginPasswordStrengthTimerRef.current = setTimeout(() => {
      editLoginPasswordStrengthTimerRef.current = null;

      if (editLoginPasswordStrengthRequestRef.current !== requestId) {
        return;
      }

      const password = editPasswordRef.current?.value ?? '';

      if (!password) {
        setEditLoginPasswordStrength(null);
        setEditLoginPasswordStrengthLoading(false);

        return;
      }

      const context = [
        editNameRef.current?.value ?? '',
        editUsernameRef.current?.value ?? '',
        editUrlRef.current?.value ?? '',
      ];

      setEditLoginPasswordStrengthLoading(true);

      void evaluatePasswordStrength(password, context).then((assessment) => {
        if (editLoginPasswordStrengthRequestRef.current !== requestId) {
          return;
        }

        setEditLoginPasswordStrength(assessment);
        setEditLoginPasswordStrengthLoading(false);
      });
    }, 350);
  }, []);

  const clearVaultUiState = useCallback(() => {
    vaultItemsRef.current = [];
    deletedVaultItemsRef.current = [];
    selectedItemIdRef.current = null;
    vaultSyncCursorRef.current = null;
    vaultSyncInFlightRef.current = false;

    vaultSearchGenerationRef.current += 1;

    setVaultSearchEntries([]);
    setVaultSearchQuery('');
    setVaultSearchIndexing(false);
    setVaultSearchIndexError('');

    setVaultItems([]);
    setSelectedLogin(null);
    setSelectedItemId(null);
    setEditingLogin(false);
    setDeletedVaultItems([]);
    setNewLoginPasswordVisible(false);
    setSelectedLoginPasswordVisible(false);
    setEditLoginPasswordVisible(false);

    clearNewLoginPasswordStrength();
    clearEditLoginPasswordStrength();

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
  }, [clearNewLoginPasswordStrength, clearEditLoginPasswordStrength]);

  const disposeUnlockedVault = useCallback(() => {
    const unlocked = unlockedVaultRef.current;

    if (!unlocked) {
      return;
    }

    /*
     * Prevent new vault operations from starting immediately.
     * If a local search-index decrypt is already in flight,
     * keep this WASM instance alive until that build settles.
     */
    unlockedVaultRef.current = null;
    unlockedVaultIdRef.current = null;

    vaultSearchGenerationRef.current += 1;

    const searchBuild = vaultSearchBuildPromiseRef.current;

    const dispose = () => {
      unlocked.clear();
      unlocked.free();
    };

    if (searchBuild) {
      void searchBuild.then(dispose, dispose);

      return;
    }

    dispose();
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

        navigate(routes.vault, {
          replace: true,
        });
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

        const deletingSelectedItem = selectedItemId === itemId;

        if (deletingSelectedItem) {
          selectedItemIdRef.current = null;

          setEditingLogin(false);
          setSelectedLoginPasswordVisible(false);
          setEditLoginPasswordVisible(false);

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

        if (deletingSelectedItem) {
          navigate(routes.vault, {
            replace: true,
          });
        }

        setError(
          'This item changed in another client. Review the latest revision before deleting it.',
        );

        return;
      }

      if (error instanceof ApiError && error.code === 'ITEM_NOT_FOUND') {
        const deletingSelectedItem = selectedItemId === itemId;

        if (deletingSelectedItem) {
          selectedItemIdRef.current = null;

          setEditingLogin(false);
          setSelectedLoginPasswordVisible(false);
          setEditLoginPasswordVisible(false);

          setSelectedLogin(null);
          setSelectedItemId(null);
        }

        await refreshVaultItems();

        if (deletingSelectedItem) {
          navigate(routes.vault, {
            replace: true,
          });
        }

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
    const redirectTo = resolveRuntimeRedirect(runtimeState, location.pathname);

    if (!redirectTo) {
      return;
    }

    navigate(redirectTo, {
      replace: true,
    });
  }, [runtimeState, location.pathname, navigate]);

  useEffect(() => {
    if (!editingLogin) {
      return;
    }

    /*
     * The edit form has now committed, so its
     * uncontrolled DOM refs are available.
     */
    scheduleEditLoginPasswordStrength();

    return () => {
      /*
       * Invalidate pending work without calling
       * React setState from the effect cleanup.
       */
      editLoginPasswordStrengthRequestRef.current += 1;

      if (editLoginPasswordStrengthTimerRef.current) {
        clearTimeout(editLoginPasswordStrengthTimerRef.current);

        editLoginPasswordStrengthTimerRef.current = null;
      }
    };
  }, [editingLogin, selectedItemId, scheduleEditLoginPasswordStrength]);

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

    await rebuildVaultSearchIndex(collections.activeItems);
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
    resetMessages();

    if (!registrationId) {
      setError('Registration state is missing. Restart account creation.');

      return;
    }

    if (!bootstrapToken) {
      setError('Passkey bootstrap state is missing. Create your passkey again.');

      return;
    }

    const masterPassword = masterPasswordRef.current?.value ?? '';

    const confirmation = confirmMasterPasswordRef.current?.value ?? '';

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
    recoveryKitRef.current = null;
    recoveryKitRouteRef.current = null;

    setRecoveryKitLoaded(false);

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
      recoveryKitRouteRef.current = location.pathname;

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
        setVaultSearchEntries([]);
        setVaultSearchQuery('');
        setVaultSearchIndexError('');
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

  async function handleChangeMasterPassword() {
    const user = authenticatedUser;

    const recoveryKit = recoveryKitRef.current;

    const currentMasterPassword = changeCurrentMasterPasswordRef.current?.value ?? '';

    const newMasterPassword = changeNewMasterPasswordRef.current?.value ?? '';

    const confirmation = changeConfirmMasterPasswordRef.current?.value ?? '';

    resetMessages();

    if (!user || !recoveryKit) {
      setError('Recovery Kit is required.');

      return;
    }

    if (!currentMasterPassword) {
      setError('Current Master Password is required.');

      return;
    }

    if (newMasterPassword.length < 12) {
      setError('New Master Password must contain at least 12 characters.');

      return;
    }

    if (newMasterPassword !== confirmation) {
      setError('Master Password confirmation does not match.');

      return;
    }

    setLoading(true);

    try {
      await changeVaultMasterPassword({
        currentMasterPassword,

        newMasterPassword,

        recoveryKit,

        authenticatedEmail: user.email,
      });

      /*
       * Successful Master Password change revokes
       * every server session, including this one.
       *
       * No local vault state should survive that
       * security transition.
       */
      disposeUnlockedVault();

      clearVaultUiState();

      discardRecoveryKit();

      setAuthenticatedUser(null);

      setRuntimeState('SIGNED_OUT');

      setMessage(
        'Master Password changed successfully. Sign in again with your passkey, then unlock the vault with your new Master Password.',
      );
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        disposeUnlockedVault();

        clearVaultUiState();

        discardRecoveryKit();

        setAuthenticatedUser(null);

        setRuntimeState('SIGNED_OUT');

        setError(
          'Your session has expired. Authenticate again before changing your Master Password.',
        );

        return;
      }

      if (error instanceof ApiError && error.code === 'MASTER_PASSWORD_CHANGE_CONFLICT') {
        setError(
          'The cryptographic state changed while updating your Master Password. Reload the Recovery Kit and try again.',
        );

        return;
      }

      /*
       * A wrong current Master Password fails
       * locally while WASM tries to unwrap the ARK.
       *
       * Do not expose low-level crypto errors.
       */
      setError(
        'Master Password could not be changed. Verify your current Master Password and try again.',
      );
    } finally {
      if (changeCurrentMasterPasswordRef.current) {
        changeCurrentMasterPasswordRef.current.value = '';
      }

      if (changeNewMasterPasswordRef.current) {
        changeNewMasterPasswordRef.current.value = '';
      }

      if (changeConfirmMasterPasswordRef.current) {
        changeConfirmMasterPasswordRef.current.value = '';
      }

      setLoading(false);
    }
  }

  async function handleRecoverMasterPassword() {
    const user = authenticatedUser;

    const recoveryKit = recoveryKitRef.current;

    const newMasterPassword = recoveryNewMasterPasswordRef.current?.value ?? '';

    const confirmation = recoveryConfirmMasterPasswordRef.current?.value ?? '';

    resetMessages();

    if (!user || !recoveryKit) {
      setError('Recovery Kit is required.');

      return;
    }

    if (newMasterPassword.length < 12) {
      setError('New Master Password must contain at least 12 characters.');

      return;
    }

    if (newMasterPassword !== confirmation) {
      setError('Master Password confirmation does not match.');

      return;
    }

    const confirmed = window.confirm(
      'Recover your Master Password? This will replace the current Master Password and sign out every authenticated session.',
    );

    if (!confirmed) {
      return;
    }

    setLoading(true);

    try {
      await recoverVaultMasterPassword({
        newMasterPassword,

        recoveryKit,

        authenticatedEmail: user.email,
      });

      /*
       * Recovery revokes every authenticated
       * server session. No authenticated or
       * decrypted client state may survive.
       */
      disposeUnlockedVault();

      clearVaultUiState();

      discardRecoveryFlowState();

      /*
       * Invalidate any outstanding Security
       * session request before removing its UI state.
       */
      securitySessionsRequestRef.current += 1;

      setManagedSessions([]);

      setAuthenticatedUser(null);

      setRuntimeState('SIGNED_OUT');

      setError('');

      setMessage('Master Password recovered successfully. Sign in again with your passkey.');

      navigate(routes.login, {
        replace: true,
      });
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        disposeUnlockedVault();

        clearVaultUiState();

        discardRecoveryFlowState();

        securitySessionsRequestRef.current += 1;

        setManagedSessions([]);

        setAuthenticatedUser(null);

        setRuntimeState('SIGNED_OUT');

        setMessage('');

        setError(
          'Your session has expired. Authenticate again before recovering your Master Password.',
        );

        navigate(routes.login, {
          replace: true,
        });

        return;
      }

      if (error instanceof ApiError && error.code === 'RECOVERY_CONFLICT') {
        discardRecoveryFlowState();

        setMessage('');

        setError(
          'The cryptographic state changed during recovery. Load your Recovery Kit again and retry.',
        );

        return;
      }

      setMessage('');

      setError(error instanceof Error ? error.message : 'Master Password recovery failed.');
    } finally {
      /*
       * Password plaintext must not survive
       * any recovery attempt.
       */
      if (recoveryNewMasterPasswordRef.current) {
        recoveryNewMasterPasswordRef.current.value = '';
      }

      if (recoveryConfirmMasterPasswordRef.current) {
        recoveryConfirmMasterPasswordRef.current.value = '';
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
      setNewLoginPasswordVisible(false);

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
        setNewLoginPasswordVisible(false);
        clearNewLoginPasswordStrength();
      }

      setLoading(false);
    }
  }

  function handleGenerateNewLoginPassword() {
    const passwordInput = loginPasswordRef.current;

    if (!passwordInput) {
      return;
    }

    resetMessages();

    passwordInput.value = generatePassword();

    scheduleNewLoginPasswordStrength();

    setMessage('Password generated locally.');
  }

  function handleGenerateEditLoginPassword() {
    const passwordInput = editPasswordRef.current;

    if (!passwordInput) {
      return;
    }

    resetMessages();

    passwordInput.value = generatePassword();

    scheduleEditLoginPasswordStrength();

    setMessage('Password generated locally.');
  }

  function handleViewLoginItem(itemId: string) {
    resetMessages();

    navigate(routes.vaultItem(itemId));
  }

  const loadRoutedLoginItem = useCallback(
    async (itemId: string) => {
      if (routedItemLoadRef.current === itemId) {
        return;
      }

      const vault = unlockedVaultRef.current;

      const vaultId = unlockedVaultIdRef.current;

      if (!vault || !vaultId) {
        setError('Vault is locked.');

        return;
      }

      routedItemLoadRef.current = itemId;

      setLoading(true);

      setError('');
      setMessage('');

      /*
       * Drop plaintext belonging to the
       * previously selected item before
       * decrypting another item.
       */
      selectedItemIdRef.current = null;

      setEditingLogin(false);

      setSelectedLoginPasswordVisible(false);
      setEditLoginPasswordVisible(false);

      setSelectedLogin(null);
      setSelectedItemId(null);
      try {
        const login = await loadAndDecryptLoginItem(vault, vaultId, itemId);

        selectedItemIdRef.current = itemId;

        setSelectedItemId(itemId);
        setSelectedLogin(login);
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) {
          disposeUnlockedVault();

          clearVaultUiState();

          setAuthenticatedUser(null);

          setRuntimeState('SIGNED_OUT');

          setError('Your session has expired. Authenticate again.');

          return;
        }

        if (error instanceof ApiError && error.code === 'ITEM_NOT_FOUND') {
          navigate(routes.vault, {
            replace: true,
          });

          setError('This vault item no longer exists.');

          return;
        }

        setError(error instanceof Error ? error.message : 'Login could not be decrypted.');
      } finally {
        if (routedItemLoadRef.current === itemId) {
          routedItemLoadRef.current = null;
        }

        setLoading(false);
      }
    },
    [clearVaultUiState, disposeUnlockedVault, navigate],
  );

  useEffect(() => {
    if (runtimeState !== 'UNLOCKED') {
      return;
    }

    let cancelled = false;

    queueMicrotask(() => {
      if (cancelled) {
        return;
      }

      /*
       * Leaving an item route must discard
       * any decrypted plaintext from React state.
       */
      if (!routedVaultItemId) {
        selectedItemIdRef.current = null;

        setEditingLogin(false);

        setSelectedLoginPasswordVisible(false);
        setEditLoginPasswordVisible(false);

        setSelectedLogin(null);
        setSelectedItemId(null);

        if (editPasswordRef.current) {
          editPasswordRef.current.value = '';
        }

        return;
      }

      /*
       * The requested route already matches
       * the decrypted item currently in memory.
       */
      if (selectedItemId === routedVaultItemId) {
        return;
      }

      void loadRoutedLoginItem(routedVaultItemId);
    });

    return () => {
      cancelled = true;
    };
  }, [runtimeState, routedVaultItemId, selectedItemId, loadRoutedLoginItem]);

  function handleCloseLoginItem() {
    navigate(routes.vault);
  }

  function handleStartEditingLogin() {
    if (!selectedLogin || !selectedItemId) {
      return;
    }

    clearEditLoginPasswordStrength();

    setEditingLogin(true);

    resetMessages();
  }

  function handleCancelEditingLogin() {
    setEditingLogin(false);
    setEditLoginPasswordVisible(false);

    if (editPasswordRef.current) {
      editPasswordRef.current.value = '';
      clearEditLoginPasswordStrength();
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
      setEditLoginPasswordVisible(false);
      setSelectedLoginPasswordVisible(false);

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
        selectedItemIdRef.current = null;

        setEditingLogin(false);
        setSelectedLoginPasswordVisible(false);
        setEditLoginPasswordVisible(false);

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

        navigate(routes.vault, {
          replace: true,
        });

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
        clearEditLoginPasswordStrength();
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

    setManagedSessions([]);

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

      await rebuildVaultSearchIndex(activeItems);
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

    navigate(routes.login, {
      replace: true,
    });
  }

  const discardRecoveryKit = useCallback(() => {
    recoveryKitRef.current = null;
    recoveryKitRouteRef.current = null;

    setRecoveryKitLoaded(false);

    if (recoveryKitFileRef.current) {
      recoveryKitFileRef.current.value = '';
    }
  }, []);

  function discardRecoveryFlowState() {
    discardRecoveryKit();

    if (recoveryNewMasterPasswordRef.current) {
      recoveryNewMasterPasswordRef.current.value = '';
    }

    if (recoveryConfirmMasterPasswordRef.current) {
      recoveryConfirmMasterPasswordRef.current.value = '';
    }
  }

  useEffect(() => {
    if (!recoveryKitLoaded) {
      return;
    }

    const loadedForRoute = recoveryKitRouteRef.current;

    if (loadedForRoute === location.pathname && runtimeState === 'AUTHENTICATED_LOCKED') {
      return;
    }

    let cancelled = false;

    queueMicrotask(() => {
      if (cancelled) {
        return;
      }

      discardRecoveryKit();
    });

    return () => {
      cancelled = true;
    };
  }, [recoveryKitLoaded, location.pathname, runtimeState, discardRecoveryKit]);

  async function refreshSecuritySessions(showError: boolean): Promise<void> {
    const requestId = ++securitySessionsRequestRef.current;

    setSecuritySessionsLoading(true);

    try {
      const sessions = await listSessions();

      if (securitySessionsRequestRef.current !== requestId) {
        return;
      }

      setManagedSessions(sessions);
    } catch (error) {
      if (securitySessionsRequestRef.current !== requestId) {
        return;
      }

      if (error instanceof ApiError && error.status === 401) {
        disposeUnlockedVault();

        discardRecoveryKit();

        clearVaultUiState();

        setManagedSessions([]);

        setAuthenticatedUser(null);

        setRuntimeState('SIGNED_OUT');

        setError('Your session has expired. Authenticate again.');

        return;
      }

      if (showError) {
        setError(error instanceof Error ? error.message : 'Sessions could not be loaded.');
      }
    } finally {
      if (securitySessionsRequestRef.current === requestId) {
        setSecuritySessionsLoading(false);
      }
    }
  }

  useEffect(() => {
    let cancelled = false;

    const securityRouteActive =
      isSecurityRoute && (runtimeState === 'AUTHENTICATED_LOCKED' || runtimeState === 'UNLOCKED');

    if (!securityRouteActive) {
      securitySessionsRequestRef.current += 1;

      queueMicrotask(() => {
        if (cancelled) {
          return;
        }

        setManagedSessions([]);
        setSecuritySessionsLoading(false);
      });

      return () => {
        cancelled = true;
        securitySessionsRequestRef.current += 1;
      };
    }

    const requestId = ++securitySessionsRequestRef.current;

    queueMicrotask(() => {
      if (cancelled) {
        return;
      }

      setSecuritySessionsLoading(true);

      void listSessions()
        .then((sessions) => {
          if (cancelled || securitySessionsRequestRef.current !== requestId) {
            return;
          }

          setManagedSessions(sessions);
        })
        .catch((error: unknown) => {
          if (cancelled || securitySessionsRequestRef.current !== requestId) {
            return;
          }

          if (error instanceof ApiError && error.status === 401) {
            disposeUnlockedVault();

            discardRecoveryKit();

            clearVaultUiState();

            setManagedSessions([]);

            setAuthenticatedUser(null);

            setRuntimeState('SIGNED_OUT');

            setError('Your session has expired. Authenticate again.');

            return;
          }

          /*
           * Automatic loading is best-effort.
           * Manual refresh exposes the error.
           */
        })
        .finally(() => {
          if (!cancelled && securitySessionsRequestRef.current === requestId) {
            setSecuritySessionsLoading(false);
          }
        });
    });

    return () => {
      cancelled = true;

      securitySessionsRequestRef.current += 1;
    };
  }, [isSecurityRoute, runtimeState, clearVaultUiState, discardRecoveryKit, disposeUnlockedVault]);

  async function refreshManagedSessions(): Promise<void> {
    const sessions = await listSessions();

    setManagedSessions(sessions);
  }

  async function handleRevokeManagedSession(sessionId: string, current: boolean) {
    resetMessages();

    setLoading(true);

    try {
      await revokeSession(sessionId);

      if (current) {
        /*
         * Revoking the current session destroys
         * the authenticated security boundary.
         */
        disposeUnlockedVault();

        discardRecoveryKit();

        clearVaultUiState();

        setManagedSessions([]);

        setAuthenticatedUser(null);

        setRuntimeState('SIGNED_OUT');

        setMessage('Current session signed out.');

        return;
      }

      await refreshManagedSessions();

      setMessage('Session revoked.');
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        disposeUnlockedVault();

        discardRecoveryKit();

        clearVaultUiState();

        setManagedSessions([]);

        setAuthenticatedUser(null);

        setRuntimeState('SIGNED_OUT');

        setError('Your session has expired. Authenticate again.');

        return;
      }

      setError(error instanceof Error ? error.message : 'Session could not be revoked.');
    } finally {
      setLoading(false);
    }
  }

  async function handleRevokeOtherSessions() {
    resetMessages();

    setLoading(true);

    try {
      await revokeOtherSessions();

      await refreshManagedSessions();

      setMessage('All other sessions have been signed out.');
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        disposeUnlockedVault();

        discardRecoveryKit();

        clearVaultUiState();

        setManagedSessions([]);

        setAuthenticatedUser(null);

        setRuntimeState('SIGNED_OUT');

        setError('Your session has expired. Authenticate again.');

        return;
      }

      setError(error instanceof Error ? error.message : 'Other sessions could not be revoked.');
    } finally {
      setLoading(false);
    }
  }

  async function handleLoadSessions() {
    resetMessages();

    await refreshSecuritySessions(true);
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

          {isVaultRoute && (
            <>
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

              <hr />

              <button
                type="button"
                disabled={loading}
                onClick={() => {
                  navigate(routes.security);
                }}
              >
                Security settings
              </button>

              <button
                type="button"
                disabled={loading}
                onClick={() => {
                  navigate(routes.recovery);
                }}
              >
                Recover Master Password
              </button>
            </>
          )}

          {isSecurityRoute && (
            <>
              <hr />

              <h3>Security settings</h3>

              <p>
                <strong>Vault status:</strong> Locked
              </p>

              <p>
                Your account is authenticated, but vault keys are not loaded in this browser
                session.
              </p>

              <button
                type="button"
                disabled={loading}
                onClick={() => {
                  navigate(routes.vault);
                }}
              >
                Back to vault
              </button>

              <hr />

              <h4>Sessions</h4>

              <p>Review and revoke authenticated sessions for your account.</p>

              <button
                type="button"
                disabled={loading || securitySessionsLoading}
                onClick={handleLoadSessions}
              >
                {securitySessionsLoading ? 'Loading sessions…' : 'Refresh sessions'}
              </button>

              {managedSessions.length > 1 && (
                <button
                  type="button"
                  disabled={loading || securitySessionsLoading}
                  onClick={handleRevokeOtherSessions}
                >
                  Sign out other sessions
                </button>
              )}

              {managedSessions.length > 0 && (
                <ul>
                  {managedSessions.map((session) => (
                    <li key={session.id}>
                      <strong>{session.deviceLabel}</strong>
                      {session.current && ' — Current session'}
                      <br />
                      Last active: {new Date(session.lastSeenAt).toLocaleString()}
                      <br />
                      Expires: {new Date(session.absoluteExpiresAt).toLocaleString()}
                      <br />
                      <button
                        type="button"
                        disabled={loading || securitySessionsLoading}
                        onClick={() => {
                          void handleRevokeManagedSession(session.id, session.current);
                        }}
                      >
                        {session.current ? 'Sign out this session' : 'Sign out'}
                      </button>
                    </li>
                  ))}
                </ul>
              )}

              <hr />

              <h4>Master Password</h4>

              <p>
                Changing your Master Password re-wraps the account root key. Existing vault items
                are not re-encrypted.
              </p>

              <p>Load your Recovery Kit locally to continue.</p>

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
                  <div>
                    <input
                      ref={changeCurrentMasterPasswordRef}
                      type="password"
                      placeholder="Current Master Password"
                      autoComplete="current-password"
                    />
                  </div>

                  <div>
                    <input
                      ref={changeNewMasterPasswordRef}
                      type="password"
                      placeholder="New Master Password"
                      autoComplete="new-password"
                    />
                  </div>

                  <div>
                    <input
                      ref={changeConfirmMasterPasswordRef}
                      type="password"
                      placeholder="Confirm new Master Password"
                      autoComplete="new-password"
                    />
                  </div>

                  <button type="button" disabled={loading} onClick={handleChangeMasterPassword}>
                    Change Master Password
                  </button>
                </>
              )}

              <hr />

              <h4>Account recovery</h4>

              <p>
                If you no longer know your current Master Password, use the recovery flow instead.
              </p>

              <button
                type="button"
                disabled={loading}
                onClick={() => {
                  navigate(routes.recovery);
                }}
              >
                Recover Master Password
              </button>

              <hr />

              <button type="button" disabled={loading} onClick={handleLogout}>
                Sign out
              </button>
            </>
          )}

          {isRecoveryRoute && (
            <>
              <hr />

              <h3>Recover Master Password</h3>

              <p>
                <strong>Vault status:</strong> Locked
              </p>

              <p>
                Recovery lets you replace a forgotten Master Password while keeping the existing
                account and vault encryption keys.
              </p>

              <p>
                Completing recovery will revoke every authenticated session, including this one. You
                will need to sign in again with your passkey.
              </p>

              <hr />

              <h4>Recovery Kit</h4>

              {!recoveryKitLoaded ? (
                <>
                  <p>
                    Load your Recovery Kit locally. The file is processed only inside this browser
                    and is not uploaded to the server.
                  </p>

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
                </>
              ) : (
                <>
                  <p>Recovery Kit loaded for this recovery session.</p>

                  <button type="button" disabled={loading} onClick={discardRecoveryFlowState}>
                    Discard Recovery Kit
                  </button>

                  <hr />

                  <h4>New Master Password</h4>

                  <div>
                    <input
                      ref={recoveryNewMasterPasswordRef}
                      type="password"
                      placeholder="New Master Password"
                      autoComplete="new-password"
                    />
                  </div>

                  <div>
                    <input
                      ref={recoveryConfirmMasterPasswordRef}
                      type="password"
                      placeholder="Confirm new Master Password"
                      autoComplete="new-password"
                    />
                  </div>

                  <button type="button" disabled={loading} onClick={handleRecoverMasterPassword}>
                    {loading ? 'Recovering…' : 'Recover Master Password'}
                  </button>
                </>
              )}

              <hr />

              <button
                type="button"
                disabled={loading}
                onClick={() => {
                  navigate(routes.vault);
                }}
              >
                Cancel recovery
              </button>
            </>
          )}
        </section>
      )}

      {runtimeState === 'UNLOCKED' && authenticatedUser && (
        <section>
          <h2>Vault unlocked</h2>

          <p>
            Signed in as <strong>{authenticatedUser.email}</strong>
          </p>

          <p>Vault keys are available only inside the local WASM runtime.</p>

          {isVaultRoute && (
            <>
              <button
                type="button"
                disabled={loading}
                onClick={() => {
                  navigate(routes.security);
                }}
              >
                Security settings
              </button>

              <hr />

              <h3>New login</h3>

              <div>
                <label>
                  Name
                  <input
                    ref={loginNameRef}
                    type="text"
                    autoComplete="off"
                    placeholder="GitHub"
                    onChange={scheduleNewLoginPasswordStrength}
                  />
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
                    onChange={scheduleNewLoginPasswordStrength}
                  />
                </label>
              </div>

              <div>
                <label>
                  Password
                  <input
                    ref={loginPasswordRef}
                    type={newLoginPasswordVisible ? 'text' : 'password'}
                    autoComplete="off"
                    placeholder="Password"
                    onChange={scheduleNewLoginPasswordStrength}
                  />
                </label>

                <button type="button" disabled={loading} onClick={handleGenerateNewLoginPassword}>
                  Generate password
                </button>

                <button
                  type="button"
                  disabled={loading}
                  onClick={() => {
                    setNewLoginPasswordVisible((visible) => !visible);
                  }}
                >
                  {newLoginPasswordVisible ? 'Hide password' : 'Show password'}
                </button>
              </div>

              <PasswordStrengthFeedback
                assessment={newLoginPasswordStrength}
                loading={newLoginPasswordStrengthLoading}
              />

              <div>
                <label>
                  URL
                  <input
                    ref={loginUrlRef}
                    type="url"
                    autoComplete="off"
                    placeholder="https://example.com"
                    onChange={scheduleNewLoginPasswordStrength}
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

              <h3>Vault items ({vaultListView.totalCount})</h3>

              <div>
                <label>
                  Search
                  <input
                    type="search"
                    value={vaultSearchQuery}
                    placeholder="Search name, username, or URL"
                    autoComplete="off"
                    onChange={(event) => {
                      setVaultSearchQuery(event.target.value);
                    }}
                  />
                </label>

                {vaultListView.hasQuery && (
                  <button
                    type="button"
                    disabled={loading}
                    onClick={() => {
                      setVaultSearchQuery('');
                    }}
                  >
                    Clear search
                  </button>
                )}
              </div>

              <button
                type="button"
                disabled={loading || vaultSearchIndexing}
                onClick={() => {
                  void refreshVaultItems();
                }}
              >
                Refresh
              </button>

              {vaultSearchIndexing && <p>Building local search index…</p>}

              {vaultSearchIndexError && <p role="alert">{vaultSearchIndexError}</p>}

              {vaultItems.length === 0 ? (
                <p>No saved logins yet.</p>
              ) : vaultSearchIndexing &&
                vaultSearchEntries.length === 0 ? null : vaultSearchEntries.length === 0 ? (
                <p>No vault items could be indexed locally.</p>
              ) : (
                <>
                  {vaultListView.hasQuery ? (
                    <p>
                      Showing {vaultListView.visibleCount} of {vaultListView.totalCount}{' '}
                      {vaultListView.totalCount === 1 ? 'login' : 'logins'}.
                    </p>
                  ) : (
                    <p>
                      {vaultListView.totalCount}{' '}
                      {vaultListView.totalCount === 1 ? 'login' : 'logins'}.
                    </p>
                  )}

                  {vaultListView.emptyState === 'NO_SEARCH_RESULTS' ? (
                    <p>No logins match your search.</p>
                  ) : (
                    <ul>
                      {vaultListView.entries.map((entry) => (
                        <li key={entry.itemId}>
                          <div>
                            <strong>{entry.name}</strong>
                          </div>

                          {entry.username && <div>{entry.username}</div>}

                          {entry.urls[0] && <div>{entry.urls[0]}</div>}

                          <div>
                            <button
                              type="button"
                              disabled={loading || vaultSearchIndexing}
                              onClick={() => {
                                handleViewLoginItem(entry.itemId);
                              }}
                            >
                              View
                            </button>{' '}
                            <button
                              type="button"
                              disabled={loading || vaultSearchIndexing}
                              onClick={() => {
                                void handleDeleteLoginItem(entry.itemId);
                              }}
                            >
                              Delete
                            </button>
                          </div>
                        </li>
                      ))}
                    </ul>
                  )}
                </>
              )}

              <h3>Deleted items ({deletedVaultItems.length})</h3>

              <p>
                Deleted items are retained temporarily so their deletion state can synchronize
                across clients.
              </p>

              {deletedVaultItems.length === 0 ? (
                <p>No deleted items.</p>
              ) : (
                <ul>
                  {deletedVaultItems.map((item) => (
                    <li key={item.id}>
                      <div>
                        <strong>Deleted login</strong>
                      </div>

                      <div>
                        Item ID: <code>{item.id}</code>
                      </div>

                      <div>Revision: {item.revisionNumber}</div>

                      {item.deletedAt && (
                        <div>Deleted: {new Date(item.deletedAt).toLocaleString()}</div>
                      )}

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
            </>
          )}

          {isVaultItemRoute && (
            <>
              <hr />

              <button
                type="button"
                disabled={loading}
                onClick={() => {
                  navigate(routes.vault);
                }}
              >
                Back to vault
              </button>

              {loading && !selectedLogin && <p>Loading login…</p>}

              {!loading && !selectedLogin && <p>Vault item could not be loaded.</p>}

              {selectedLogin && selectedItemId && (
                <>
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
                        <strong>Password:</strong>{' '}
                        {selectedLoginPasswordVisible ? (
                          <code>{selectedLogin.password}</code>
                        ) : (
                          <code>••••••••••••</code>
                        )}
                      </p>

                      <button
                        type="button"
                        onClick={() => {
                          setSelectedLoginPasswordVisible((visible) => !visible);
                        }}
                      >
                        {selectedLoginPasswordVisible ? 'Hide password' : 'Show password'}
                      </button>

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
                            onChange={scheduleEditLoginPasswordStrength}
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
                            onChange={scheduleEditLoginPasswordStrength}
                          />
                        </label>
                      </div>

                      <div>
                        <label>
                          Password
                          <input
                            ref={editPasswordRef}
                            type={editLoginPasswordVisible ? 'text' : 'password'}
                            autoComplete="off"
                            defaultValue={selectedLogin.password}
                            onChange={scheduleEditLoginPasswordStrength}
                          />
                        </label>

                        <button
                          type="button"
                          disabled={loading}
                          onClick={handleGenerateEditLoginPassword}
                        >
                          Generate password
                        </button>

                        <button
                          type="button"
                          disabled={loading}
                          onClick={() => {
                            setEditLoginPasswordVisible((visible) => !visible);
                          }}
                        >
                          {editLoginPasswordVisible ? 'Hide password' : 'Show password'}
                        </button>
                      </div>

                      <PasswordStrengthFeedback
                        assessment={editLoginPasswordStrength}
                        loading={editLoginPasswordStrengthLoading}
                      />

                      <div>
                        <label>
                          URL
                          <input
                            ref={editUrlRef}
                            type="url"
                            autoComplete="off"
                            defaultValue={selectedLogin.urls[0] ?? ''}
                            onChange={scheduleEditLoginPasswordStrength}
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
            </>
          )}

          {isSecurityRoute && (
            <>
              <hr />

              <h3>Security settings</h3>

              <p>
                <strong>Vault status:</strong> Unlocked
              </p>

              <p>
                Vault keys are currently available only inside the local WASM runtime for this
                browser session.
              </p>

              <button
                type="button"
                disabled={loading}
                onClick={() => {
                  navigate(routes.vault);
                }}
              >
                Back to vault
              </button>

              <hr />

              <h4>Sessions</h4>

              <p>Review and revoke authenticated sessions for your account.</p>

              <button
                type="button"
                disabled={loading || securitySessionsLoading}
                onClick={handleLoadSessions}
              >
                {securitySessionsLoading ? 'Loading sessions…' : 'Refresh sessions'}
              </button>

              {managedSessions.length > 1 && (
                <button
                  type="button"
                  disabled={loading || securitySessionsLoading}
                  onClick={handleRevokeOtherSessions}
                >
                  Sign out other sessions
                </button>
              )}

              {managedSessions.length > 0 && (
                <ul>
                  {managedSessions.map((session) => (
                    <li key={session.id}>
                      <strong>{session.deviceLabel}</strong>
                      {session.current && ' — Current session'}
                      <br />
                      Last active: {new Date(session.lastSeenAt).toLocaleString()}
                      <br />
                      Expires: {new Date(session.absoluteExpiresAt).toLocaleString()}
                      <br />
                      <button
                        type="button"
                        disabled={loading || securitySessionsLoading}
                        onClick={() => {
                          void handleRevokeManagedSession(session.id, session.current);
                        }}
                      >
                        {session.current ? 'Sign out this session' : 'Sign out'}
                      </button>
                    </li>
                  ))}
                </ul>
              )}

              <hr />

              <h4>Master Password</h4>

              <p>
                Lock the vault before changing your Master Password. This removes unlocked vault
                keys from memory before entering the key-management flow.
              </p>

              <button
                type="button"
                disabled={loading}
                onClick={() => {
                  handleLockVault();

                  navigate(routes.security, {
                    replace: true,
                  });
                }}
              >
                Lock vault to change Master Password
              </button>
            </>
          )}

          {(isVaultRoute || isVaultItemRoute) && (
            <>
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
            </>
          )}

          <hr />

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
          {isLoginRoute && (
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

              <hr />

              <p>Need an account?</p>

              <button
                type="button"
                disabled={loading}
                onClick={() => {
                  navigate(routes.register);
                }}
              >
                Create account
              </button>
            </section>
          )}

          {isRegisterRoute && (
            <>
              {!registrationId && !completedAccount && (
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

                  <hr />

                  <button
                    type="button"
                    disabled={loading}
                    onClick={() => {
                      navigate(routes.login);
                    }}
                  >
                    Sign in instead
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

                  <button
                    type="button"
                    disabled={loading || !verificationToken}
                    onClick={verifyEmail}
                  >
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
        </>
      )}

      {!webAuthnSupported && <p role="alert">This browser does not support WebAuthn.</p>}

      {message && <p>{message}</p>}

      {error && <p role="alert">{error}</p>}
    </main>
  );
}
