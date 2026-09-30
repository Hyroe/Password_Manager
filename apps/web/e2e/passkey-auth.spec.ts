import { expect, test, type Page } from '@playwright/test';

interface RegistrationResponse {
  registrationId: string;
}

interface VerificationMessageResponse {
  token: string;
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
  }, testInfo) => {
    const email = `e2e-passkey-${Date.now()}-${testInfo.workerIndex}@example.com`;

    const masterPassword = 'E2E Master Password 2026!';

    /*
     * Must happen before the page touches
     * WebAuthn.
     */
    await context.credentials.install();

    await page.goto('/register');

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
     * Verify zero-knowledge transport boundary.
     */
    const serializedVaultRequests = vaultRequestBodies.join('\n');

    for (const plaintext of [...Object.values(login), ...Object.values(updatedLogin)]) {
      expect(serializedVaultRequests).not.toContain(plaintext);
    }
  });
});
