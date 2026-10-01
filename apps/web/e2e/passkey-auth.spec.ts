import { expect, test, type Page } from '@playwright/test';

interface RegistrationResponse {
  registrationId: string;
}

interface VerificationMessageResponse {
  token: string;
}

interface CsrfTokenResponse {
  csrfToken: string;
}

async function unlockVault(
  page: Page,
  recoveryKitPath: string,
  masterPassword: string,
): Promise<void> {
  await page.getByLabel('Recovery Kit').setInputFiles(recoveryKitPath);

  const unlockButton = page.getByRole('button', {
    name: 'Unlock vault',
  });

  await expect(unlockButton).toBeVisible();

  await page
    .getByPlaceholder('Master Password', {
      exact: true,
    })
    .fill(masterPassword);

  await unlockButton.click();

  await expect(
    page.getByRole('heading', {
      name: 'Vault unlocked',
    }),
  ).toBeVisible({
    timeout: 30_000,
  });
}

test.describe('real passkey authentication', () => {
  test('registers and authenticates with a real virtual passkey', async ({
    page,
    context,
    browser,
  }, testInfo) => {
    const email = `e2e-passkey-${Date.now()}-${testInfo.workerIndex}@example.com`;

    const masterPassword = 'E2E Master Password 2026!';

    const changedMasterPassword = 'E2E Changed Master Password 2026!';

    const recoveredMasterPassword = 'E2E Recovered Master Password 2026!';

    /*
     * Must happen before the page touches
     * WebAuthn.
     */
    await context.credentials.install();

    const initialDocumentResponse = await page.goto('/register');

    expect(initialDocumentResponse).not.toBeNull();

    const documentHeaders = initialDocumentResponse?.headers();

    expect(documentHeaders?.['x-content-type-options']).toBe('nosniff');

    expect(documentHeaders?.['x-frame-options']).toBe('DENY');

    expect(documentHeaders?.['referrer-policy']).toBe('no-referrer');

    expect(documentHeaders?.['cross-origin-opener-policy']).toBe('same-origin');

    expect(documentHeaders?.['cross-origin-resource-policy']).toBe('same-origin');

    expect(documentHeaders?.['permissions-policy']).toBe(
      'camera=(), geolocation=(), microphone=(), payment=(), usb=()',
    );

    const documentCsp = documentHeaders?.['content-security-policy'];

    expect(documentCsp).toContain("default-src 'none'");

    expect(documentCsp).toContain("script-src 'self' 'wasm-unsafe-eval'");

    expect(documentCsp).toContain("frame-ancestors 'none'");

    expect(documentCsp).not.toContain('upgrade-insecure-requests');

    expect(documentHeaders?.['strict-transport-security']).toBeUndefined();

    await expect(
      page.getByRole('heading', {
        name: 'Create account',
      }),
    ).toBeVisible();

    await page.getByPlaceholder('you@example.com').fill(email);

    const registrationResponsePromise = page.waitForResponse(
      (response) =>
        response.url().endsWith('/api/v1/accounts') && response.request().method() === 'POST',
    );

    await page
      .getByRole('button', {
        name: 'Start registration',
      })
      .click();

    const registrationResponse = await registrationResponsePromise;

    expect(registrationResponse.status()).toBe(202);

    const registration = (await registrationResponse.json()) as RegistrationResponse;

    await expect(
      page.getByRole('heading', {
        name: 'Verify email',
      }),
    ).toBeVisible();

    /*
     * Read the token from the injected
     * E2E EmailSender, not logs and not DB.
     */
    const verificationResponse = await context.request.get(
      `http://localhost:5173/__e2e/verification/${registration.registrationId}`,
    );

    expect(verificationResponse.ok()).toBe(true);

    const verification = (await verificationResponse.json()) as VerificationMessageResponse;

    await page.getByPlaceholder('Verification token').fill(verification.token);

    await page
      .getByRole('button', {
        name: 'Verify email',
      })
      .click();

    await expect(
      page.getByRole('heading', {
        name: 'Create passkey',
      }),
    ).toBeVisible();

    /*
     * This invokes the real frontend
     * SimpleWebAuthn startRegistration()
     * flow and navigator.credentials.create().
     */
    await page
      .getByRole('button', {
        name: 'Create passkey',
      })
      .click();

    await expect(
      page.getByRole('heading', {
        name: 'Protect your vault',
      }),
    ).toBeVisible();

    /*
     * Verify that the browser authenticator
     * really received the credential.
     */
    const credentials = await context.credentials.get({
      rpId: 'localhost',
    });

    expect(credentials).toHaveLength(1);

    expect(credentials[0]?.id).toBeTruthy();

    /*
     * Complete cryptographic onboarding.
     */
    await page
      .getByPlaceholder('Master Password', {
        exact: true,
      })
      .fill(masterPassword);

    await page
      .getByPlaceholder('Confirm Master Password', {
        exact: true,
      })
      .fill(masterPassword);

    const createVaultKeysButton = page.getByRole('button', {
      name: 'Create vault keys',
    });

    const cryptoOptionsResponsePromise = page.waitForResponse(
      (response) =>
        response.url().endsWith('/api/v1/accounts/crypto/options') &&
        response.request().method() === 'POST',
    );

    await createVaultKeysButton.click();

    const cryptoOptionsResponse = await cryptoOptionsResponsePromise;

    expect(cryptoOptionsResponse.status()).toBe(200);

    await expect(
      page.getByRole('heading', {
        name: 'Save Recovery Kit',
      }),
    ).toBeVisible({
      timeout: 60_000,
    });

    const saveRecoveryKitHeading = page.getByRole('heading', {
      name: 'Save Recovery Kit',
    });

    const bootstrapError = page.getByRole('alert');

    await expect(saveRecoveryKitHeading.or(bootstrapError)).toBeVisible({
      timeout: 30_000,
    });

    if (await bootstrapError.isVisible()) {
      throw new Error(
        `Crypto bootstrap failed: ${(await bootstrapError.textContent()) ?? 'Unknown error'}`,
      );
    }

    await expect(saveRecoveryKitHeading).toBeVisible();

    const downloadPromise = page.waitForEvent('download');

    await page
      .getByRole('button', {
        name: 'Download Recovery Kit',
      })
      .click();

    const download = await downloadPromise;

    const recoveryKitPath = testInfo.outputPath('recovery-kit.json');

    await download.saveAs(recoveryKitPath);

    await download.delete();

    await expect(
      page.getByRole('heading', {
        name: 'Activate account',
      }),
    ).toBeVisible();

    await page
      .getByRole('button', {
        name: 'Activate account',
      })
      .click();

    await expect(
      page.getByRole('heading', {
        name: 'Account ready',
      }),
    ).toBeVisible();

    await page
      .getByRole('button', {
        name: 'Continue to sign in',
      })
      .click();

    await expect(page).toHaveURL(/\/login$/);

    await expect(
      page.getByRole('heading', {
        name: 'Sign in',
      }),
    ).toBeVisible();

    /*
     * Real authentication ceremony:
     *
     * frontend
     *   ↓
     * login/options
     *   ↓
     * navigator.credentials.get()
     *   ↓
     * virtual authenticator signs challenge
     *   ↓
     * login/verify
     *   ↓
     * backend verifies assertion
     */
    await page
      .getByRole('button', {
        name: 'Sign in with passkey',
      })
      .click();

    await expect(page).toHaveURL(/\/vault$/);

    await expect(
      page.getByRole('heading', {
        name: 'Vault locked',
      }),
    ).toBeVisible();

    await expect(
      page.getByText('Authentication successful. Your vault is still locked.'),
    ).toBeVisible();

    /*
     * Authentication MUST NOT unlock
     * the cryptographic vault.
     */
    await expect(
      page.getByRole('button', {
        name: 'Lock vault',
      }),
    ).not.toBeVisible();

    /*
     * Verify that authentication created
     * an HttpOnly browser session.
     */
    const cookies = await context.cookies();

    const sessionCookie = cookies.find((cookie) => cookie.name.includes('pm_session'));

    expect(sessionCookie).toBeDefined();

    expect(sessionCookie?.httpOnly).toBe(true);

    /*
     * M1.13B4 — CSRF / Origin adversarial validation.
     *
     * A real authenticated browser session now exists.
     * Prove that safe requests remain usable while
     * authenticated mutations fail closed.
     */

    const safeGetWithoutCsrf = await page.evaluate(async () => {
      const response = await fetch('/api/v1/me', {
        method: 'GET',
        credentials: 'same-origin',
      });

      return response.status;
    });

    expect(safeGetWithoutCsrf).toBe(200);

    /*
     * Browser mutation without the synchronizer token.
     */
    const missingCsrf = await page.evaluate(async () => {
      const response = await fetch('/api/v1/auth/logout', {
        method: 'POST',
        credentials: 'same-origin',

        headers: {
          'Content-Type': 'application/json',
        },

        body: JSON.stringify({}),
      });

      const body = (await response.json()) as {
        error?: {
          code?: string;
        };
      };

      return {
        status: response.status,
        code: body.error?.code,
      };
    });

    expect(missingCsrf).toEqual({
      status: 403,
      code: 'INVALID_CSRF',
    });

    /*
     * A random attacker-controlled token must fail too.
     */
    const forgedCsrf = await page.evaluate(async () => {
      const response = await fetch('/api/v1/auth/logout', {
        method: 'POST',
        credentials: 'same-origin',

        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': 'forged-e2e-csrf-token',
        },

        body: JSON.stringify({}),
      });

      const body = (await response.json()) as {
        error?: {
          code?: string;
        };
      };

      return {
        status: response.status,
        code: body.error?.code,
      };
    });

    expect(forgedCsrf).toEqual({
      status: 403,
      code: 'INVALID_CSRF',
    });

    /*
     * Obtain the genuine token for this real session.
     */
    const initialCsrfResponse = await context.request.get('http://localhost:5173/api/v1/auth/csrf');

    expect(initialCsrfResponse.status()).toBe(200);

    const { csrfToken: initialCsrfToken } = (await initialCsrfResponse.json()) as CsrfTokenResponse;

    expect(initialCsrfToken).toBeTruthy();

    /*
     * Even a valid session + valid CSRF token must fail
     * when the Origin is not trusted.
     */
    const forgedOriginResponse = await context.request.post(
      'http://localhost:5173/api/v1/auth/logout',
      {
        headers: {
          Origin: 'https://attacker.example',
          'X-CSRF-Token': initialCsrfToken,
        },
      },
    );

    expect(forgedOriginResponse.status()).toBe(403);

    const forgedOriginBody = (await forgedOriginResponse.json()) as {
      error?: {
        code?: string;
      };
    };

    expect(forgedOriginBody.error?.code).toBe('FORBIDDEN');

    /*
     * None of the rejected attacks may revoke or
     * otherwise damage the authenticated session.
     */
    const sessionAfterRejectedAttacks = await context.request.get(
      'http://localhost:5173/api/v1/me',
    );

    expect(sessionAfterRejectedAttacks.status()).toBe(200);

    /*
     * Complete the matrix with a valid authenticated
     * mutation. There are no other sessions yet, so
     * revoke-others has no destructive side effect.
     */
    const validCsrfMutation = await context.request.post(
      'http://localhost:5173/api/v1/sessions/revoke-others',
      {
        headers: {
          Origin: 'http://localhost:5173',
          'X-CSRF-Token': initialCsrfToken,
        },
      },
    );

    expect(validCsrfMutation.ok()).toBe(true);

    const sessionAfterValidMutation = await context.request.get('http://localhost:5173/api/v1/me');

    expect(sessionAfterValidMutation.status()).toBe(200);

    /*
     * Server authentication survives a
     * document reload, but the vault stays
     * cryptographically locked.
     */
    await page.reload();

    await expect(page).toHaveURL(/\/vault$/);

    await expect(
      page.getByRole('heading', {
        name: 'Vault locked',
      }),
    ).toBeVisible();

    /*
     * Unlock using the real Recovery Kit,
     * Account Secret and Master Password.
     */
    await unlockVault(page, recoveryKitPath, masterPassword);

    await expect(
      page.getByRole('button', {
        name: 'Lock vault',
      }),
    ).toBeVisible();

    /*
     * Explicit lock destroys the in-memory
     * UnlockedVault while keeping the
     * authenticated server session.
     */
    await page
      .getByRole('button', {
        name: 'Lock vault',
      })
      .click();

    await expect(
      page.getByRole('heading', {
        name: 'Vault locked',
      }),
    ).toBeVisible();

    await expect(page).toHaveURL(/\/vault$/);

    /*
     * handleLockVault() also discards the
     * locally loaded Recovery Kit, so the
     * user must load it again.
     */
    await unlockVault(page, recoveryKitPath, masterPassword);

    /*
     * A full document reload destroys the
     * WASM runtime and its unwrapped keys.
     *
     * The HttpOnly authenticated session
     * survives, so the resulting state must
     * be AUTHENTICATED_LOCKED, not SIGNED_OUT
     * and not UNLOCKED.
     */
    await page.reload();

    await expect(page).toHaveURL(/\/vault$/);

    await expect(
      page.getByRole('heading', {
        name: 'Vault locked',
      }),
    ).toBeVisible({
      timeout: 10_000,
    });

    await expect(
      page.getByRole('heading', {
        name: 'Vault unlocked',
      }),
    ).not.toBeVisible();

    await expect(
      page.getByRole('button', {
        name: 'Lock vault',
      }),
    ).not.toBeVisible();

    /*
     * H2A — Real encrypted LOGIN CRUD.
     */
    await unlockVault(page, recoveryKitPath, masterPassword);

    const login = {
      name: 'E2E Vault Login 9841',
      username: 'e2e-user-9841@example.com',
      password: 'Vault-E2E-Password-9841!',
      url: 'https://example.com/e2e-9841',
      notes: 'E2E encrypted notes 9841',
    };

    const updatedLogin = {
      name: 'E2E Vault Login Updated 9841',
      username: 'updated-e2e-9841@example.com',
      password: 'Updated-Vault-Password-9841!',
      url: 'https://example.com/e2e-9841-updated',
      notes: 'Updated encrypted notes 9841',
    };

    /*
     * Capture vault mutation bodies.
     *
     * Plaintext LOGIN fields must never cross
     * the client/server boundary.
     */
    const vaultRequestBodies: string[] = [];

    page.on('request', (request) => {
      if (request.url().includes('/api/v1/vaults/') && request.method() !== 'GET') {
        const body = request.postData();

        if (body) {
          vaultRequestBodies.push(body);
        }
      }
    });

    /*
     * CREATE
     */
    await page
      .getByLabel('Name', {
        exact: true,
      })
      .fill(login.name);

    await page
      .getByLabel('Username', {
        exact: true,
      })
      .fill(login.username);

    await page
      .getByLabel('Password', {
        exact: true,
      })
      .fill(login.password);

    await page
      .getByLabel('URL', {
        exact: true,
      })
      .fill(login.url);

    await page
      .getByLabel('Notes', {
        exact: true,
      })
      .fill(login.notes);

    await page
      .getByRole('button', {
        name: 'Save login',
      })
      .click();

    await expect(page.getByText('Login encrypted and saved.')).toBeVisible();

    /*
     * READ through the normal routed item UI.
     *
     * This account has only one item, so the
     * first View action deterministically opens it.
     */
    await page
      .getByRole('button', {
        name: 'View',
      })
      .first()
      .click();

    await expect(page).toHaveURL(/\/vault\/items\/[^/]+$/);

    await expect(
      page.getByRole('heading', {
        name: 'Decrypted login',
      }),
    ).toBeVisible();

    await expect(
      page
        .getByText('Name:', {
          exact: true,
        })
        .locator('..'),
    ).toContainText(login.name);

    await expect(
      page
        .getByText('Username:', {
          exact: true,
        })
        .locator('..'),
    ).toContainText(login.username);

    await expect(
      page.getByText(login.url, {
        exact: true,
      }),
    ).toBeVisible();

    await expect(
      page
        .getByText('Notes:', {
          exact: true,
        })
        .locator('..'),
    ).toContainText(login.notes);

    /*
     * Password remains hidden by default.
     */
    await expect(
      page.getByText(login.password, {
        exact: true,
      }),
    ).not.toBeVisible();

    await page
      .getByRole('button', {
        name: 'Show password',
      })
      .click();

    await expect(
      page.getByText(login.password, {
        exact: true,
      }),
    ).toBeVisible();

    /*
     * UPDATE
     */
    await page
      .getByRole('button', {
        name: 'Edit',
      })
      .click();

    const editHeading = page.getByRole('heading', {
      name: 'Edit login',
    });

    await expect(editHeading).toBeVisible();

    await page.getByLabel('Name', { exact: true }).fill(updatedLogin.name);

    await expect(editHeading).toBeVisible();

    await page.getByLabel('Username', { exact: true }).fill(updatedLogin.username);

    await expect(editHeading).toBeVisible();

    await page.getByLabel('Password', { exact: true }).fill(updatedLogin.password);

    await expect(editHeading).toBeVisible();

    await page.getByLabel('URL', { exact: true }).fill(updatedLogin.url);

    await expect(editHeading).toBeVisible();

    /*
     * If this assertion passes, Notes must
     * still belong to the active edit form.
     */
    await page
      .getByRole('textbox', {
        name: 'Notes',
        exact: true,
      })
      .fill(updatedLogin.notes);

    await page
      .getByRole('button', {
        name: 'Save changes',
      })
      .click();

    await expect(page.getByText('Login updated to revision 2.')).toBeVisible();

    await expect(
      page
        .getByText('Name:', {
          exact: true,
        })
        .locator('..'),
    ).toContainText(updatedLogin.name);

    await expect(
      page
        .getByText('Username:', {
          exact: true,
        })
        .locator('..'),
    ).toContainText(updatedLogin.username);

    await expect(
      page.getByText(updatedLogin.url, {
        exact: true,
      }),
    ).toBeVisible();

    await expect(
      page
        .getByText('Notes:', {
          exact: true,
        })
        .locator('..'),
    ).toContainText(updatedLogin.notes);

    /*
     * Updated password must also remain
     * hidden by default after the persisted
     * revision is loaded back.
     */
    await expect(
      page.getByText(updatedLogin.password, {
        exact: true,
      }),
    ).not.toBeVisible();

    await page
      .getByRole('button', {
        name: 'Show password',
      })
      .click();

    await expect(
      page.getByText(updatedLogin.password, {
        exact: true,
      }),
    ).toBeVisible();

    /*
     * H2B — Search, delete, restore and reload.
     */

    /*
     * Return from the routed item view to the
     * vault list while keeping the same
     * in-memory UnlockedVault instance.
     */
    await page
      .getByRole('button', {
        name: 'Back to vault',
      })
      .click();

    await expect(page).toHaveURL(/\/vault$/);

    /*
     * Client-side search must not trigger
     * vault network traffic.
     */
    const searchInput = page.getByRole('searchbox');

    await expect(searchInput).toBeVisible();

    let captureSearchRequests = false;

    const searchNetworkRequests: string[] = [];

    page.on('request', (request) => {
      if (captureSearchRequests && request.url().includes('/api/v1/vaults/')) {
        searchNetworkRequests.push(`${request.method()} ${request.url()}`);
      }
    });

    captureSearchRequests = true;

    await searchInput.fill(updatedLogin.username);

    /*
     * Give React effects enough time to run.
     * Search itself must remain purely local.
     */
    await page.waitForTimeout(300);

    captureSearchRequests = false;

    expect(searchNetworkRequests).toEqual([]);

    /*
     * The updated item is found from the
     * locally decrypted search index.
     */
    await expect(
      page.getByText(updatedLogin.name, {
        exact: true,
      }),
    ).toBeVisible();

    /*
     * A query with no match must distinguish
     * "no search results" from an empty vault.
     */
    await searchInput.fill('definitely-no-e2e-login-match-9841');

    await expect(page.getByText('No logins match your search.')).toBeVisible();

    await searchInput.fill('');

    await expect(
      page.getByText(updatedLogin.name, {
        exact: true,
      }),
    ).toBeVisible();

    /*
     * DELETE
     *
     * Accept the deliberate destructive-action
     * confirmation dialog.
     */
    page.once('dialog', async (dialog) => {
      expect(dialog.type()).toBe('confirm');
      await dialog.accept();
    });

    await page
      .getByRole('button', {
        name: 'Delete',
      })
      .first()
      .click();

    await expect(page.getByText('Login deleted.')).toBeVisible();

    await expect(page.getByText('No saved logins yet.')).toBeVisible();

    /*
     * Deleted entries are tombstone metadata.
     * Their decrypted LOGIN presentation must
     * no longer remain in the active list.
     */
    await expect(
      page.getByText(updatedLogin.name, {
        exact: true,
      }),
    ).not.toBeVisible();

    const restoreButton = page.getByRole('button', {
      name: 'Restore',
    });

    await expect(restoreButton).toBeVisible();

    /*
     * RESTORE
     */
    await restoreButton.click();

    await expect(page.getByText('Login restored.')).toBeVisible();

    await expect(
      page.getByText(updatedLogin.name, {
        exact: true,
      }),
    ).toBeVisible();

    await expect(
      page.getByRole('button', {
        name: 'Restore',
      }),
    ).not.toBeVisible();

    /*
     * Open the restored item and prove the
     * same revision still decrypts correctly.
     */
    await page
      .getByRole('button', {
        name: 'View',
      })
      .first()
      .click();

    await expect(
      page.getByRole('heading', {
        name: 'Decrypted login',
      }),
    ).toBeVisible();

    await expect(
      page
        .getByText('Name:', {
          exact: true,
        })
        .locator('..'),
    ).toContainText(updatedLogin.name);

    await expect(
      page
        .getByText('Username:', {
          exact: true,
        })
        .locator('..'),
    ).toContainText(updatedLogin.username);

    /*
     * Full reload destroys the client-side
     * WASM key state.
     */
    await page.reload();

    await expect(page).toHaveURL(/\/vault$/);

    await expect(
      page.getByRole('heading', {
        name: 'Vault locked',
      }),
    ).toBeVisible();

    /*
     * Unlock again. bootstrapVaultSync()
     * must rebuild local state from the
     * encrypted server snapshot/change feed.
     */
    await unlockVault(page, recoveryKitPath, masterPassword);

    await expect(
      page.getByText(updatedLogin.name, {
        exact: true,
      }),
    ).toBeVisible();

    /*
     * Decrypt again after the completely new
     * WASM unlock/runtime lifecycle.
     */
    await page
      .getByRole('button', {
        name: 'View',
      })
      .first()
      .click();

    await expect(
      page
        .getByText('Name:', {
          exact: true,
        })
        .locator('..'),
    ).toContainText(updatedLogin.name);

    await expect(
      page
        .getByText('Username:', {
          exact: true,
        })
        .locator('..'),
    ).toContainText(updatedLogin.username);

    await expect(
      page.getByText(updatedLogin.url, {
        exact: true,
      }),
    ).toBeVisible();

    await expect(
      page
        .getByText('Notes:', {
          exact: true,
        })
        .locator('..'),
    ).toContainText(updatedLogin.notes);

    /*
     * H3A1 — Current authenticated session lifecycle.
     *
     * Start from the restored unlocked vault.
     */
    await page
      .getByRole('button', {
        name: 'Back to vault',
      })
      .click();

    await expect(page).toHaveURL(/\/vault$/);

    /*
     * SPA navigation into Security must preserve
     * the current authenticated/unlocked runtime.
     */
    await page
      .getByRole('button', {
        name: 'Security settings',
      })
      .click();

    await expect(page).toHaveURL(/\/settings\/security$/);

    await expect(
      page.getByRole('heading', {
        name: 'Security settings',
      }),
    ).toBeVisible();

    await expect(
      page
        .getByText('Vault status:', {
          exact: true,
        })
        .locator('..'),
    ).toContainText('Unlocked');

    /*
     * Sessions load automatically when the
     * Security route becomes active.
     */
    await expect(
      page.getByRole('heading', {
        name: 'Sessions',
      }),
    ).toBeVisible();

    await expect(
      page.getByText('Current session', {
        exact: false,
      }),
    ).toBeVisible({
      timeout: 10_000,
    });

    /*
     * Also exercise the manual refresh action.
     */
    const refreshSessionsButton = page.getByRole('button', {
      name: 'Refresh sessions',
    });

    await expect(refreshSessionsButton).toBeVisible();

    await refreshSessionsButton.click();

    await expect(
      page.getByText('Current session', {
        exact: false,
      }),
    ).toBeVisible();

    const signOutCurrentSession = page.getByRole('button', {
      name: 'Sign out this session',
    });

    await expect(signOutCurrentSession).toBeVisible();

    /*
     * The account currently has only this
     * authenticated browser session.
     */
    await expect(
      page.getByRole('button', {
        name: 'Sign out other sessions',
      }),
    ).not.toBeVisible();

    /*
     * Revoke the authoritative server session.
     *
     * This must also destroy:
     * - authenticated client state
     * - UnlockedVault
     * - loaded Recovery Kit
     * - decrypted vault UI state
     */
    await signOutCurrentSession.click();

    await expect(page).toHaveURL(/\/login$/);

    await expect(
      page.getByRole('heading', {
        name: 'Sign in',
      }),
    ).toBeVisible();

    await expect(page.getByText('Current session signed out.')).toBeVisible();

    /*
     * The server must no longer accept the old
     * opaque session, not merely hide the UI.
     */
    const revokedSessionResponse = await context.request.get('http://localhost:5173/api/v1/me');

    expect(revokedSessionResponse.status()).toBe(401);

    /*
     * Protected routes must remain unavailable.
     */
    await page.goto('/vault');

    await expect(page).toHaveURL(/\/login$/);

    /*
     * Authenticate again with the existing
     * real virtual passkey so later H3 tests
     * can continue from a valid session.
     */
    await page
      .getByRole('button', {
        name: 'Sign in with passkey',
      })
      .click();

    await expect(page).toHaveURL(/\/vault$/);

    await expect(
      page.getByRole('heading', {
        name: 'Vault locked',
      }),
    ).toBeVisible();

    const reauthenticatedCookies = await context.cookies();

    const reauthenticatedSession = reauthenticatedCookies.find((cookie) =>
      cookie.name.includes('pm_session'),
    );

    expect(reauthenticatedSession).toBeDefined();

    expect(reauthenticatedSession?.httpOnly).toBe(true);

    /*
     * H3A2 — Revoke another authenticated session.
     *
     * Create a second isolated browser context
     * representing another device/browser session.
     */
    /*
     * H3A2 — Revoke another authenticated session.
     *
     * We need two real server sessions, not two
     * independent copies of the same WebAuthn
     * authenticator.
     */

    if (!reauthenticatedSession) {
      throw new Error('Reauthenticated session cookie is unavailable.');
    }

    /*
     * Preserve session A.
     *
     * Clearing the cookie locally does NOT call
     * logout, so session A remains valid server-side.
     */
    const firstSessionCookie = reauthenticatedSession;

    await context.clearCookies({
      name: firstSessionCookie.name,
    });

    /*
     * Reload forces the application to discover
     * that this browser no longer presents
     * session A.
     */
    await page.reload();

    await expect(page).toHaveURL(/\/login$/);

    await expect(
      page.getByRole('heading', {
        name: 'Sign in',
      }),
    ).toBeVisible();

    /*
     * Use the SAME original virtual authenticator.
     * Its WebAuthn state continues naturally.
     *
     * This creates session B.
     */
    await page
      .getByRole('button', {
        name: 'Sign in with passkey',
      })
      .click();

    await expect(page).toHaveURL(/\/vault$/);

    await expect(
      page.getByRole('heading', {
        name: 'Vault locked',
      }),
    ).toBeVisible();

    /*
     * Session B is now the primary/current session.
     */
    const primarySessionResponse = await context.request.get('http://localhost:5173/api/v1/me');

    expect(primarySessionResponse.status()).toBe(200);

    /*
     * Create another isolated browser context
     * containing the still-valid session A.
     *
     * No WebAuthn clone is required.
     */
    const secondContext = await browser.newContext({
      storageState: {
        cookies: [firstSessionCookie],
        origins: [],
      },
    });

    try {
      const secondPage = await secondContext.newPage();

      await secondPage.goto('http://localhost:5173/vault');

      /*
       * Session A is genuinely still valid.
       */
      await expect(
        secondPage.getByRole('heading', {
          name: 'Vault locked',
        }),
      ).toBeVisible();

      const secondSessionBeforeRevocation = await secondContext.request.get(
        'http://localhost:5173/api/v1/me',
      );

      expect(secondSessionBeforeRevocation.status()).toBe(200);

      /*
       * M1.13B4 — CSRF tokens must be bound to the
       * authoritative server session.
       *
       * Primary context = session B.
       * Secondary context = preserved session A.
       */

      const primarySessionCsrfResponse = await context.request.get(
        'http://localhost:5173/api/v1/auth/csrf',
      );

      expect(primarySessionCsrfResponse.status()).toBe(200);

      const { csrfToken: primarySessionCsrfToken } =
        (await primarySessionCsrfResponse.json()) as CsrfTokenResponse;

      const secondarySessionCsrfResponse = await secondContext.request.get(
        'http://localhost:5173/api/v1/auth/csrf',
      );

      expect(secondarySessionCsrfResponse.status()).toBe(200);

      const { csrfToken: secondarySessionCsrfToken } =
        (await secondarySessionCsrfResponse.json()) as CsrfTokenResponse;

      expect(secondarySessionCsrfToken).not.toBe(primarySessionCsrfToken);

      /*
       * Present session A's CSRF token together with
       * session B's cookie.
       *
       * Origin is deliberately valid so the rejection
       * specifically proves session/token binding.
       */
      const crossSessionCsrfResponse = await context.request.post(
        'http://localhost:5173/api/v1/auth/logout',
        {
          headers: {
            Origin: 'http://localhost:5173',

            'X-CSRF-Token': secondarySessionCsrfToken,
          },
        },
      );

      expect(crossSessionCsrfResponse.status()).toBe(403);

      const crossSessionCsrfBody = (await crossSessionCsrfResponse.json()) as {
        error?: {
          code?: string;
        };
      };

      expect(crossSessionCsrfBody.error?.code).toBe('INVALID_CSRF');

      /*
       * Rejection must leave both sessions intact.
       */
      const primaryAfterCrossSessionAttempt = await context.request.get(
        'http://localhost:5173/api/v1/me',
      );

      expect(primaryAfterCrossSessionAttempt.status()).toBe(200);

      const secondaryAfterCrossSessionAttempt = await secondContext.request.get(
        'http://localhost:5173/api/v1/me',
      );

      expect(secondaryAfterCrossSessionAttempt.status()).toBe(200);

      /*
       * Primary session B manages the account.
       */
      await page.goto('/settings/security');

      await expect(
        page.getByRole('heading', {
          name: 'Security settings',
        }),
      ).toBeVisible();

      await page
        .getByRole('button', {
          name: 'Refresh sessions',
        })
        .click();

      const signOutOtherSessions = page.getByRole('button', {
        name: 'Sign out other sessions',
      });

      await expect(signOutOtherSessions).toBeVisible();

      await expect(
        page.getByText('Current session', {
          exact: false,
        }),
      ).toHaveCount(1);

      /*
       * Revoke session A while preserving
       * current session B.
       */
      await signOutOtherSessions.click();

      await expect(page.getByText('All other sessions have been signed out.')).toBeVisible();

      /*
       * Current session B survives.
       */
      const primaryAfterRevocation = await context.request.get('http://localhost:5173/api/v1/me');

      expect(primaryAfterRevocation.status()).toBe(200);

      /*
       * Session A is revoked authoritatively
       * by the backend.
       */
      const secondSessionAfterRevocation = await secondContext.request.get(
        'http://localhost:5173/api/v1/me',
      );

      expect(secondSessionAfterRevocation.status()).toBe(401);

      await expect(
        page.getByRole('button', {
          name: 'Sign out other sessions',
        }),
      ).not.toBeVisible();

      await expect(
        page.getByRole('button', {
          name: 'Sign out this session',
        }),
      ).toBeVisible();

      /*
       * The secondary browser discovers the
       * server-side revocation normally.
       */
      await secondPage.reload();

      await expect(secondPage).toHaveURL(/\/login$/);

      await expect(
        secondPage.getByRole('heading', {
          name: 'Sign in',
        }),
      ).toBeVisible();
    } finally {
      await secondContext.close();
    }

    /*
     * H3B — Change Master Password.
     *
     * H3A2 leaves the primary browser authenticated,
     * vault locked and on Security settings.
     */
    await expect(page).toHaveURL(/\/settings\/security$/);

    await expect(
      page
        .getByText('Vault status:', {
          exact: true,
        })
        .locator('..'),
    ).toContainText('Locked');

    /*
     * Track vault-item mutations during the
     * Master Password change.
     *
     * Re-wrapping the ARK must not rewrite
     * individual encrypted vault items.
     */
    const masterPasswordVaultMutations: string[] = [];

    let captureMasterPasswordChange = false;

    page.on('request', (request) => {
      if (!captureMasterPasswordChange) {
        return;
      }

      const path = new URL(request.url()).pathname;

      if (
        path.includes('/api/v1/vaults/') &&
        path.includes('/items') &&
        request.method() !== 'GET'
      ) {
        masterPasswordVaultMutations.push(`${request.method()} ${path}`);
      }
    });

    /*
     * Load the real Recovery Kit.
     */
    await page.getByLabel('Recovery Kit').setInputFiles(recoveryKitPath);

    await expect(
      page.getByText('Recovery Kit loaded locally. It has not been uploaded to the server.'),
    ).toBeVisible();

    /*
     * Submit current + new Master Password.
     */
    await page
      .getByPlaceholder('Current Master Password', {
        exact: true,
      })
      .fill(masterPassword);

    await page
      .getByPlaceholder('New Master Password', {
        exact: true,
      })
      .fill(changedMasterPassword);

    await page
      .getByPlaceholder('Confirm new Master Password', {
        exact: true,
      })
      .fill(changedMasterPassword);

    captureMasterPasswordChange = true;

    await page
      .getByRole('button', {
        name: 'Change Master Password',
      })
      .click();

    /*
     * Successful change revokes every session,
     * including the one performing the change.
     */
    await expect(page).toHaveURL(/\/login$/, {
      timeout: 30_000,
    });

    captureMasterPasswordChange = false;

    await expect(
      page.getByRole('heading', {
        name: 'Sign in',
      }),
    ).toBeVisible();

    await expect(
      page.getByText(
        'Master Password changed successfully. Sign in again with your passkey, then unlock the vault with your new Master Password.',
      ),
    ).toBeVisible();

    /*
     * No vault item was rewritten.
     */
    expect(masterPasswordVaultMutations).toEqual([]);

    /*
     * The old authenticated session is
     * authoritatively revoked server-side.
     */
    const sessionAfterMasterPasswordChange = await context.request.get(
      'http://localhost:5173/api/v1/me',
    );

    expect(sessionAfterMasterPasswordChange.status()).toBe(401);

    /*
     * Authenticate again using the same real
     * passkey. Authentication remains separate
     * from vault unlocking.
     */
    await page
      .getByRole('button', {
        name: 'Sign in with passkey',
      })
      .click();

    await expect(page).toHaveURL(/\/vault$/);

    await expect(
      page.getByRole('heading', {
        name: 'Vault locked',
      }),
    ).toBeVisible();

    /*
     * Load the same Recovery Kit.
     */
    await page.getByLabel('Recovery Kit').setInputFiles(recoveryKitPath);

    const unlockButton = page.getByRole('button', {
      name: 'Unlock vault',
    });

    await expect(unlockButton).toBeVisible();

    /*
     * OLD Master Password must no longer unwrap
     * the account root key.
     */
    await page
      .getByPlaceholder('Master Password', {
        exact: true,
      })
      .fill(masterPassword);

    await unlockButton.click();

    await expect(page.getByRole('alert')).toBeVisible({
      timeout: 30_000,
    });

    await expect(
      page.getByRole('heading', {
        name: 'Vault locked',
      }),
    ).toBeVisible();

    await expect(
      page.getByRole('heading', {
        name: 'Vault unlocked',
      }),
    ).not.toBeVisible();

    /*
     * NEW Master Password must unwrap the same
     * account root key successfully.
     *
     * The Recovery Kit remains loaded after the
     * failed unlock attempt.
     */
    await page
      .getByPlaceholder('Master Password', {
        exact: true,
      })
      .fill(changedMasterPassword);

    await unlockButton.click();

    await expect(
      page.getByRole('heading', {
        name: 'Vault unlocked',
      }),
    ).toBeVisible({
      timeout: 30_000,
    });

    /*
     * Existing encrypted item must still be
     * present after the key-envelope change.
     */
    await expect(
      page.getByText(updatedLogin.name, {
        exact: true,
      }),
    ).toBeVisible({
      timeout: 30_000,
    });

    await page
      .getByRole('button', {
        name: 'View',
      })
      .first()
      .click();

    await expect(
      page.getByRole('heading', {
        name: 'Decrypted login',
      }),
    ).toBeVisible();

    await expect(
      page
        .getByText('Name:', {
          exact: true,
        })
        .locator('..'),
    ).toContainText(updatedLogin.name);

    await expect(
      page
        .getByText('Username:', {
          exact: true,
        })
        .locator('..'),
    ).toContainText(updatedLogin.username);

    await expect(
      page.getByText(updatedLogin.url, {
        exact: true,
      }),
    ).toBeVisible();

    await expect(
      page
        .getByText('Notes:', {
          exact: true,
        })
        .locator('..'),
    ).toContainText(updatedLogin.notes);

    /*
     * Confirm the secret itself survived too.
     */
    await page
      .getByRole('button', {
        name: 'Show password',
      })
      .click();

    await expect(
      page.getByText(updatedLogin.password, {
        exact: true,
      }),
    ).toBeVisible();

    /*
     * H3C — Account recovery.
     *
     * H3B ends with the vault unlocked again
     * using changedMasterPassword, and proves
     * the existing item still decrypts.
     */

    /*
     * Leave the decrypted item and explicitly
     * destroy the current UnlockedVault.
     */
    await page
      .getByRole('button', {
        name: 'Back to vault',
      })
      .click();

    await page
      .getByRole('button', {
        name: 'Lock vault',
      })
      .click();

    await expect(page).toHaveURL(/\/vault$/);

    await expect(
      page.getByRole('heading', {
        name: 'Vault locked',
      }),
    ).toBeVisible();

    /*
     * Create a second real server session so
     * recovery can prove account-wide session
     * revocation, not only current-session logout.
     */
    const cookiesBeforeRecovery = await context.cookies();

    const preservedRecoverySession = cookiesBeforeRecovery.find((cookie) =>
      cookie.name.includes('pm_session'),
    );

    if (!preservedRecoverySession) {
      throw new Error('Session cookie before recovery is unavailable.');
    }

    /*
     * Remove the cookie only from this browser.
     * The server-side session remains active.
     */
    await context.clearCookies({
      name: preservedRecoverySession.name,
    });

    await page.reload();

    await expect(page).toHaveURL(/\/login$/);

    await expect(
      page.getByRole('heading', {
        name: 'Sign in',
      }),
    ).toBeVisible();

    /*
     * Establish another real session using
     * the same original virtual authenticator.
     */
    await page
      .getByRole('button', {
        name: 'Sign in with passkey',
      })
      .click();

    await expect(page).toHaveURL(/\/vault$/);

    await expect(
      page.getByRole('heading', {
        name: 'Vault locked',
      }),
    ).toBeVisible();

    /*
     * Put the preserved first session into an
     * isolated browser context.
     */
    const recoveryOtherContext = await browser.newContext({
      storageState: {
        cookies: [preservedRecoverySession],
        origins: [],
      },
    });

    try {
      const otherSessionBeforeRecovery = await recoveryOtherContext.request.get(
        'http://localhost:5173/api/v1/me',
      );

      expect(otherSessionBeforeRecovery.status()).toBe(200);

      const recoverySessionBefore = await context.request.get('http://localhost:5173/api/v1/me');

      expect(recoverySessionBefore.status()).toBe(200);

      /*
       * Enter recovery through the real UI.
       */
      await page
        .getByRole('button', {
          name: 'Recover Master Password',
        })
        .click();

      await expect(page).toHaveURL(/\/recovery$/);

      await expect(
        page.getByRole('heading', {
          name: 'Recover Master Password',
        }),
      ).toBeVisible();

      await expect(
        page
          .getByText('Vault status:', {
            exact: true,
          })
          .locator('..'),
      ).toContainText('Locked');

      /*
       * Load the original real Recovery Kit.
       */
      await page.getByLabel('Recovery Kit').setInputFiles(recoveryKitPath);

      await expect(page.getByText('Recovery Kit loaded for this recovery session.')).toBeVisible();

      await page
        .getByPlaceholder('New Master Password', {
          exact: true,
        })
        .fill(recoveredMasterPassword);

      await page
        .getByPlaceholder('Confirm new Master Password', {
          exact: true,
        })
        .fill(recoveredMasterPassword);

      /*
       * Recovery should change key-envelope state,
       * not rewrite individual vault items.
       */
      const recoveryVaultMutations: string[] = [];

      let captureRecoveryRequests = true;

      page.on('request', (request) => {
        if (!captureRecoveryRequests) {
          return;
        }

        const path = new URL(request.url()).pathname;

        if (
          path.includes('/api/v1/vaults/') &&
          path.includes('/items') &&
          request.method() !== 'GET'
        ) {
          recoveryVaultMutations.push(`${request.method()} ${path}`);
        }
      });

      /*
       * Confirm the intentionally destructive
       * account-recovery operation.
       */
      page.once('dialog', async (dialog) => {
        expect(dialog.type()).toBe('confirm');

        await dialog.accept();
      });

      await page
        .getByRole('button', {
          name: 'Recover Master Password',
        })
        .click();

      await expect(page).toHaveURL(/\/login$/, {
        timeout: 30_000,
      });

      captureRecoveryRequests = false;

      await expect(
        page.getByRole('heading', {
          name: 'Sign in',
        }),
      ).toBeVisible();

      await expect(
        page.getByText('Master Password recovered successfully. Sign in again with your passkey.'),
      ).toBeVisible();

      /*
       * Recovery must not have rewritten
       * encrypted vault items.
       */
      expect(recoveryVaultMutations).toEqual([]);

      /*
       * Recovery session is revoked.
       */
      const recoverySessionAfter = await context.request.get('http://localhost:5173/api/v1/me');

      expect(recoverySessionAfter.status()).toBe(401);

      /*
       * The other authenticated session must
       * also be revoked account-wide.
       */
      const otherSessionAfterRecovery = await recoveryOtherContext.request.get(
        'http://localhost:5173/api/v1/me',
      );

      expect(otherSessionAfterRecovery.status()).toBe(401);

      /*
       * Authenticate again after recovery.
       */
      await page
        .getByRole('button', {
          name: 'Sign in with passkey',
        })
        .click();

      await expect(page).toHaveURL(/\/vault$/);

      await expect(
        page.getByRole('heading', {
          name: 'Vault locked',
        }),
      ).toBeVisible();

      /*
       * Load the same Recovery Kit for normal
       * vault unlock.
       */
      await page.getByLabel('Recovery Kit').setInputFiles(recoveryKitPath);

      const recoveryUnlockButton = page.getByRole('button', {
        name: 'Unlock vault',
      });

      await expect(recoveryUnlockButton).toBeVisible();

      /*
       * The Master Password that was valid
       * immediately before recovery must now fail.
       */
      await page
        .getByPlaceholder('Master Password', {
          exact: true,
        })
        .fill(changedMasterPassword);

      await recoveryUnlockButton.click();

      await expect(page.getByRole('alert')).toBeVisible({
        timeout: 30_000,
      });

      await expect(
        page.getByRole('heading', {
          name: 'Vault locked',
        }),
      ).toBeVisible();

      /*
       * Recovery Kit remains loaded after the
       * failed local unwrap attempt.
       *
       * The recovered Master Password must now
       * unlock the same account root key.
       */
      await page
        .getByPlaceholder('Master Password', {
          exact: true,
        })
        .fill(recoveredMasterPassword);

      await recoveryUnlockButton.click();

      await expect(
        page.getByRole('heading', {
          name: 'Vault unlocked',
        }),
      ).toBeVisible({
        timeout: 30_000,
      });

      /*
       * Existing item survived recovery without
       * item-level re-encryption.
       */
      await expect(
        page.getByText(updatedLogin.name, {
          exact: true,
        }),
      ).toBeVisible({
        timeout: 30_000,
      });

      await page
        .getByRole('button', {
          name: 'View',
        })
        .first()
        .click();

      await expect(
        page.getByRole('heading', {
          name: 'Decrypted login',
        }),
      ).toBeVisible();

      await expect(
        page
          .getByText('Name:', {
            exact: true,
          })
          .locator('..'),
      ).toContainText(updatedLogin.name);

      await expect(
        page
          .getByText('Username:', {
            exact: true,
          })
          .locator('..'),
      ).toContainText(updatedLogin.username);

      await expect(
        page.getByText(updatedLogin.url, {
          exact: true,
        }),
      ).toBeVisible();

      await expect(
        page
          .getByText('Notes:', {
            exact: true,
          })
          .locator('..'),
      ).toContainText(updatedLogin.notes);

      await page
        .getByRole('button', {
          name: 'Show password',
        })
        .click();

      await expect(
        page.getByText(updatedLogin.password, {
          exact: true,
        }),
      ).toBeVisible();
    } finally {
      await recoveryOtherContext.close();
    }

    /*
     * H4A — Final critical-path closure.
     *
     * H3C leaves us authenticated, unlocked
     * and viewing the restored/decrypted item.
     */
    const protectedItemUrl = page.url();

    expect(protectedItemUrl).toMatch(/\/vault\/items\/[^/]+$/);

    await expect(
      page.getByRole('heading', {
        name: 'Vault unlocked',
      }),
    ).toBeVisible();

    await expect(
      page.getByText(updatedLogin.password, {
        exact: true,
      }),
    ).toBeVisible();

    /*
     * Exercise the normal user-facing logout,
     * not session-management revocation.
     */
    await page
      .getByRole('button', {
        name: 'Sign out',
      })
      .click();

    await expect(page).toHaveURL(/\/login$/);

    await expect(
      page.getByRole('heading', {
        name: 'Sign in',
      }),
    ).toBeVisible();

    await expect(page.getByText('Signed out successfully.')).toBeVisible();

    /*
     * Decrypted vault plaintext must disappear
     * with the unlocked runtime.
     */
    await expect(
      page.getByText(updatedLogin.password, {
        exact: true,
      }),
    ).not.toBeVisible();

    await expect(
      page.getByText(updatedLogin.name, {
        exact: true,
      }),
    ).not.toBeVisible();

    /*
     * Logout must revoke the authoritative
     * opaque server session.
     */
    const sessionAfterLogout = await context.request.get('http://localhost:5173/api/v1/me');

    expect(sessionAfterLogout.status()).toBe(401);

    /*
     * A reload must not resurrect authenticated
     * or decrypted client state.
     */
    await page.reload();

    await expect(page).toHaveURL(/\/login$/);

    await expect(
      page.getByRole('heading', {
        name: 'Sign in',
      }),
    ).toBeVisible();

    /*
     * Even the previously valid deep item URL
     * must now resolve back to login.
     */
    await page.goto(protectedItemUrl);

    await expect(page).toHaveURL(/\/login$/);

    await expect(
      page.getByRole('heading', {
        name: 'Sign in',
      }),
    ).toBeVisible();

    await expect(
      page.getByRole('heading', {
        name: 'Vault unlocked',
      }),
    ).not.toBeVisible();

    /*
     * Verify zero-knowledge transport boundary.
     */
    const serializedVaultRequests = vaultRequestBodies.join('\n');

    for (const plaintext of [...Object.values(login), ...Object.values(updatedLogin)]) {
      expect(serializedVaultRequests).not.toContain(plaintext);
    }
  });
});
