import { expect, test, type Page, type Route } from '@playwright/test';

const authenticatedUser = {
  id: 'user-e2e',
  email: 'e2e@example.com',
  emailVerified: true,
};

async function fulfillJson(route: Route, status: number, body: unknown): Promise<void> {
  await route.fulfill({
    status,

    contentType: 'application/json',

    body: JSON.stringify(body),
  });
}

async function mockSignedOut(page: Page): Promise<void> {
  await page.route('**/api/v1/me', async (route) => {
    await fulfillJson(route, 401, {
      error: {
        code: 'UNAUTHENTICATED',
        message: 'Authentication required.',
        requestId: 'e2e-request',
      },
    });
  });
}

async function mockAuthenticatedLocked(page: Page): Promise<void> {
  await page.route('**/api/v1/me', async (route) => {
    await fulfillJson(route, 200, {
      user: authenticatedUser,
    });
  });

  await page.route('**/api/v1/auth/csrf', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        csrfToken: 'e2e-csrf-token',
      }),
    });
  });

  await page.route('**/api/v1/sessions', async (route) => {
    if (route.request().method() !== 'GET') {
      await route.fallback();

      return;
    }

    await fulfillJson(route, 200, {
      sessions: [],
    });
  });
}

test.describe('runtime routing', () => {
  const signedOutProtectedRoutes = [
    '/vault',
    '/vault/items/item-e2e',
    '/settings/security',
    '/recovery',
  ];

  for (const path of signedOutProtectedRoutes) {
    test(`redirects signed-out user from ${path} to login`, async ({ page }) => {
      await mockSignedOut(page);

      await page.goto(path);

      await expect(page).toHaveURL(/\/login$/);

      await expect(
        page.getByRole('heading', {
          name: 'Sign in',
        }),
      ).toBeVisible();
    });
  }

  test('allows signed-out user to remain on login', async ({ page }) => {
    await mockSignedOut(page);

    await page.goto('/login');

    await expect(page).toHaveURL(/\/login$/);

    await expect(
      page.getByRole('heading', {
        name: 'Sign in',
      }),
    ).toBeVisible();
  });

  test('allows signed-out user to remain on registration', async ({ page }) => {
    await mockSignedOut(page);

    await page.goto('/register');

    await expect(page).toHaveURL(/\/register$/);

    await expect(
      page.getByRole('heading', {
        name: 'Create account',
      }),
    ).toBeVisible();
  });

  test('redirects authenticated locked user away from login', async ({ page }) => {
    await mockAuthenticatedLocked(page);

    await page.goto('/login');

    await expect(page).toHaveURL(/\/vault$/);

    await expect(
      page.getByRole('heading', {
        name: 'Vault locked',
      }),
    ).toBeVisible();
  });

  test('redirects authenticated locked user away from registration', async ({ page }) => {
    await mockAuthenticatedLocked(page);

    await page.goto('/register');

    await expect(page).toHaveURL(/\/vault$/);

    await expect(
      page.getByRole('heading', {
        name: 'Vault locked',
      }),
    ).toBeVisible();
  });

  test('prevents locked user from opening an item route', async ({ page }) => {
    await mockAuthenticatedLocked(page);

    await page.goto('/vault/items/item-e2e');

    await expect(page).toHaveURL(/\/vault$/);

    await expect(
      page.getByRole('heading', {
        name: 'Vault locked',
      }),
    ).toBeVisible();
  });

  test('allows authenticated locked user on vault', async ({ page }) => {
    await mockAuthenticatedLocked(page);

    await page.goto('/vault');

    await expect(page).toHaveURL(/\/vault$/);

    await expect(
      page.getByRole('heading', {
        name: 'Vault locked',
      }),
    ).toBeVisible();
  });

  test('allows authenticated locked user on security settings', async ({ page }) => {
    await mockAuthenticatedLocked(page);

    await page.goto('/settings/security');

    await expect(page).toHaveURL(/\/settings\/security$/);

    await expect(
      page.getByRole('heading', {
        name: 'Security settings',
      }),
    ).toBeVisible();

    await expect(page.getByText(/Vault status:\s*Locked/i)).toBeVisible();
  });

  test('allows authenticated locked user on recovery', async ({ page }) => {
    await mockAuthenticatedLocked(page);

    await page.goto('/recovery');

    await expect(page).toHaveURL(/\/recovery$/);

    await expect(
      page.getByRole('heading', {
        name: 'Recover Master Password',
      }),
    ).toBeVisible();
  });

  test('restores authenticated locked state after reload', async ({ page }) => {
    await mockAuthenticatedLocked(page);

    await page.goto('/vault');

    await expect(
      page.getByRole('heading', {
        name: 'Vault locked',
      }),
    ).toBeVisible();

    await page.reload();

    await expect(page).toHaveURL(/\/vault$/);

    await expect(
      page.getByRole('heading', {
        name: 'Vault locked',
      }),
    ).toBeVisible();
  });
});
