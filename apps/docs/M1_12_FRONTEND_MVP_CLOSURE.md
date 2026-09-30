# M1.12 — Frontend MVP Closure

**Status:** Complete

## Scope

M1.12 delivers the first complete browser-based MVP for the password manager.

The frontend preserves the separation between:

- account authentication,
- vault authentication material,
- client-side cryptographic state,
- encrypted server persistence.

## Validated Critical Path

The real browser E2E flow validates:

1. Account registration
2. Email verification
3. Real WebAuthn passkey registration
4. Client-side cryptographic bootstrap
5. Recovery Kit generation and persistence
6. Account activation
7. Real passkey authentication
8. Locked authenticated runtime
9. Vault unlock using Master Password + Recovery Kit
10. Encrypted vault item creation
11. Decryption and viewing
12. Item update
13. Local plaintext search
14. Delete and restore
15. Reload and re-unlock lifecycle
16. Current-session revocation
17. Multi-session revocation
18. Master Password change
19. Account recovery
20. Normal logout
21. Protected-route rejection after logout

## Security Properties Validated

- Master Password is never sent to the backend.
- Recovery Kit processing occurs locally.
- Vault plaintext is not sent to the backend.
- Sensitive vault metadata remains inside encrypted payloads.
- Vault search operates locally after decryption.
- Authentication does not automatically unlock the vault.
- Page reload destroys the in-memory unlocked WASM state.
- Lock and logout destroy local unlocked vault state.
- Server sessions use authoritative revocation.
- Master Password change re-wraps the account root key without rewriting vault items.
- Account recovery preserves the existing vault cryptographic hierarchy.
- Master Password change and recovery revoke authenticated sessions.
- Previously encrypted vault items remain decryptable after key-envelope changes.

## Regression Gates

The MVP closure requires the following commands to remain green:

```text
pnpm --filter @pm/web typecheck
pnpm --filter @pm/web lint
pnpm --filter @pm/web test
pnpm --filter @pm/web test:e2e
pnpm --filter @pm/web test:e2e:auth
pnpm --filter @pm/web build

pnpm --filter @pm/api typecheck
pnpm --filter @pm/api lint
pnpm --filter @pm/api test
```
