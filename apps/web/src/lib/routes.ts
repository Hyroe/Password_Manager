export const routes = {
  home: '/',

  login: '/login',

  register: '/register',

  vault: '/vault',

  vaultItemPattern: '/vault/items/:itemId',

  vaultItem: (itemId: string) => `/vault/items/${encodeURIComponent(itemId)}`,

  security: '/settings/security',

  recovery: '/recovery',
} as const;
