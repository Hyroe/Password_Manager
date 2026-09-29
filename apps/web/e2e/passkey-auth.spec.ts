import { expect, test } from '@playwright/test';

interface RegistrationResponse {
  registrationId: string;
}

interface VerificationMessageResponse {
  token: string;
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
  });
});
