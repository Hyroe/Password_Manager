# Enterprise Password Manager

## API Contract & Implementation Starting Point

**Status:** Implementation Baseline v0.1
**API Version:** `/api/v1`
**Architecture:** Zero-Knowledge Modular Monolith
**Primary Client:** Web
**Authentication:** Passkeys / WebAuthn
**Sessions:** Opaque HttpOnly Cookie
**Vault Unlock:** Master Password + Account Secret

---

# 1. Purpose

Define the minimum HTTP contract required to begin implementation.

This document intentionally avoids describing the entire future product.

The first implementation milestone must prove:

```text
Register
    ↓
Create Passkey
    ↓
Initialize Crypto
    ↓
Authenticate
    ↓
Unlock Vault
    ↓
Create Encrypted Item
    ↓
Persist Ciphertext
    ↓
Reload
    ↓
Decrypt Client-Side
```

If this works correctly, we have validated the core architecture.

---

# 2. Initial Technology Stack

Freeze the first implementation stack as:

```text
Monorepo
    pnpm workspaces

Frontend
    React
    TypeScript
    Vite

Backend
    Node.js
    TypeScript
    Express

Validation
    Zod

Database
    PostgreSQL

ORM
    Prisma

Crypto Core
    Rust
    WASM

WebAuthn
    vetted WebAuthn server/client library

Testing
    Vitest
    Supertest
    Playwright

Local Infrastructure
    Docker Compose
```

Redis and object storage are deferred until required.

---

# 3. Repository

```text
password-manager/
│
├── apps/
│   ├── web/
│   └── api/
│
├── packages/
│   ├── crypto-core/
│   ├── protocol/
│   ├── schemas/
│   └── shared-types/
│
├── security/
│   ├── 01_PRODUCT_SECURITY_BASELINE.md
│   ├── 02_THREAT_MODEL.md
│   ├── 03_CRYPTOGRAPHIC_ARCHITECTURE.md
│   ├── 04_KEY_HIERARCHY_AND_LIFECYCLE.md
│   ├── 05_SYSTEM_ARCHITECTURE.md
│   ├── 06_DATABASE_SCHEMA.md
│   ├── 07_AUTHENTICATION_AND_SESSION_PROTOCOL.md
│   └── 08_API_CONTRACT.md
│
├── infrastructure/
│   └── docker/
│
├── package.json
├── pnpm-workspace.yaml
└── docker-compose.yml
```

---

# 4. API Conventions

Base URL:

```text
/api/v1
```

JSON requests:

```http
Content-Type: application/json
```

Success responses use the resource directly.

Errors use:

```json
{
  "error": {
    "code": "ITEM_CONFLICT",
    "message": "The item has changed since it was loaded.",
    "requestId": "uuid"
  }
}
```

Do not expose:

- stack traces
- SQL errors
- crypto internals
- library exceptions

---

# 5. Authentication Rules

Endpoints are classified as:

```text
PUBLIC

AUTHENTICATED

REAUTHENTICATED

AUTHENTICATED + UNLOCKED CLIENT
```

The server can verify only:

```text
PUBLIC
AUTHENTICATED
REAUTHENTICATED
```

`UNLOCKED` is a client-side state.

The server must never ask the client to send ARK to prove unlock state.

---

# 6. CSRF Rules

Every authenticated state-changing browser request requires:

```text
valid session
+
valid CSRF token
+
valid Origin
```

Safe GET operations do not require a CSRF token.

---

# 7. Registration

## Start Account Registration

```http
POST /api/v1/accounts
```

Authentication:

```text
PUBLIC
```

Request:

```json
{
  "email": "user@example.com"
}
```

Response:

```http
202 Accepted
```

```json
{
  "registrationId": "uuid"
}
```

Server:

- validates email
- creates temporary registration
- sends verification message
- writes no active user yet

---

# 8. Verify Email

```http
POST /api/v1/accounts/verify-email
```

Request:

```json
{
  "registrationId": "uuid",
  "token": "..."
}
```

Response:

```json
{
  "registrationToken": "short-lived-token"
}
```

This token permits completion of onboarding only.

It is not an authenticated application session.

---

# 9. Passkey Registration Options

```http
POST /api/v1/auth/passkeys/register/options
```

Request:

```json
{
  "registrationToken": "..."
}
```

Response contains standard WebAuthn creation options.

Conceptually:

```json
{
  "challengeId": "uuid",
  "options": {}
}
```

---

# 10. Passkey Registration Verification

```http
POST /api/v1/auth/passkeys/register/verify
```

Request:

```json
{
  "challengeId": "uuid",
  "credential": {}
}
```

Server verifies:

- challenge
- origin
- RP ID
- signature/attestation response
- user verification

Response:

```json
{
  "bootstrapToken": "short-lived-token"
}
```

The account is still not active.

Crypto initialization must complete first.

---

# 11. Crypto Bootstrap

After WebAuthn registration, the client creates locally:

```text
Account Secret
KDF Salt
ARK
PVK
Recovery Key
```

Then derives:

```text
MPK
MKEK
Recovery KEK
```

and creates:

```text
Password ARK Envelope
Recovery ARK Envelope
PVK Envelope
```

---

# 12. Initialize Cryptographic Account

```http
POST /api/v1/accounts/crypto
```

Authentication:

```text
BOOTSTRAP_TOKEN
```

Request:

```json
{
  "protocolVersion": 1,
  "cryptoSuite": "PM-AESGCM-ARGON2ID-1",

  "kdf": {
    "algorithm": "argon2id",
    "salt": "base64",
    "memoryKiB": 65536,
    "iterations": 3,
    "parallelism": 4
  },

  "rootKeyEnvelope": {
    "keyVersion": 1,
    "algorithm": "AES-256-GCM",
    "iv": "base64",
    "ciphertext": "base64"
  },

  "recoveryEnvelope": {
    "version": 1,
    "algorithm": "AES-256-GCM",
    "iv": "base64",
    "ciphertext": "base64"
  },

  "vault": {
    "id": "uuid",
    "keyVersion": 1,
    "keyEnvelope": {
      "algorithm": "AES-256-GCM",
      "iv": "base64",
      "ciphertext": "base64"
    }
  }
}
```

The request MUST NOT contain:

```text
Master Password
Account Secret
Recovery Key
ARK
PVK
```

---

# 13. Crypto Bootstrap Response

```http
201 Created
```

```json
{
  "user": {
    "id": "uuid",
    "email": "user@example.com"
  },

  "vault": {
    "id": "uuid"
  },

  "recoveryKitRequired": true
}
```

At this point the account becomes:

```text
ACTIVE
```

---

# 14. Recovery Kit

The Recovery Kit is generated entirely client-side.

The API never receives:

```text
Account Secret
Recovery Key
```

The client should require explicit confirmation that the user stored it before considering onboarding complete from a UX perspective.

---

# 15. Passkey Login Options

```http
POST /api/v1/auth/passkeys/login/options
```

Authentication:

```text
PUBLIC
```

Response:

```json
{
  "challengeId": "uuid",
  "options": {}
}
```

---

# 16. Passkey Login Verify

```http
POST /api/v1/auth/passkeys/login/verify
```

Request:

```json
{
  "challengeId": "uuid",
  "credential": {}
}
```

Success:

```http
204 No Content
```

Response header:

```text
Set-Cookie:
__Host-pm_session=<opaque-value>;
Secure;
HttpOnly;
SameSite=Strict;
Path=/
```

Server stores only the session-token hash.

---

# 17. Current Account

```http
GET /api/v1/me
```

Authentication:

```text
AUTHENTICATED
```

Response:

```json
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "emailVerified": true
  }
}
```

No vault plaintext.

---

# 18. Crypto Unlock Material

```http
GET /api/v1/crypto/bootstrap
```

Authentication:

```text
AUTHENTICATED
```

Response:

```json
{
  "protocolVersion": 1,
  "cryptoSuite": "PM-AESGCM-ARGON2ID-1",

  "kdf": {
    "algorithm": "argon2id",
    "salt": "base64",
    "memoryKiB": 65536,
    "iterations": 3,
    "parallelism": 4
  },

  "rootKeyEnvelope": {
    "keyVersion": 1,
    "algorithm": "AES-256-GCM",
    "iv": "base64",
    "ciphertext": "base64"
  },

  "vaults": [
    {
      "id": "uuid",
      "keyVersion": 1,
      "keyEnvelope": {
        "algorithm": "AES-256-GCM",
        "iv": "base64",
        "ciphertext": "base64"
      }
    }
  ]
}
```

The client combines this with:

```text
Master Password
+
locally available Account Secret
```

to unlock ARK.

---

# 19. CSRF Token

```http
GET /api/v1/auth/csrf
```

Authentication:

```text
AUTHENTICATED
```

Response:

```json
{
  "csrfToken": "..."
}
```

---

# 20. Create Vault Item

```http
POST /api/v1/vaults/:vaultId/items
```

Requires:

```text
AUTHENTICATED
CSRF
```

The client must already be unlocked to construct the request.

Request:

```json
{
  "id": "uuid",
  "protocolVersion": 1,

  "revision": 1,

  "payload": {
    "algorithm": "AES-256-GCM",
    "iv": "base64",
    "ciphertext": "base64"
  },

  "keyEnvelope": {
    "containerKeyVersion": 1,
    "algorithm": "AES-256-GCM",
    "iv": "base64",
    "ciphertext": "base64"
  }
}
```

No plaintext fields.

---

# 21. Create Item Response

```http
201 Created
```

```json
{
  "id": "uuid",
  "revision": 1,
  "syncSequence": 1
}
```

---

# 22. List Vault Items

```http
GET /api/v1/vaults/:vaultId/items
```

Requires:

```text
AUTHENTICATED
```

Response:

```json
{
  "items": [
    {
      "id": "uuid",
      "revision": 1,
      "protocolVersion": 1,

      "payload": {
        "algorithm": "AES-256-GCM",
        "iv": "base64",
        "ciphertext": "base64"
      },

      "keyEnvelope": {
        "containerKeyVersion": 1,
        "algorithm": "AES-256-GCM",
        "iv": "base64",
        "ciphertext": "base64"
      },

      "createdAt": "...",
      "updatedAt": "..."
    }
  ]
}
```

The browser decrypts locally.

---

# 23. Get Item

```http
GET /api/v1/vaults/:vaultId/items/:itemId
```

Requires:

```text
AUTHENTICATED
```

Returns the same encrypted representation.

---

# 24. Update Item

```http
PUT /api/v1/vaults/:vaultId/items/:itemId
```

Requires:

```text
AUTHENTICATED
CSRF
```

Request:

```json
{
  "expectedRevision": 3,

  "newRevision": {
    "revision": 4,
    "protocolVersion": 1,

    "payload": {
      "algorithm": "AES-256-GCM",
      "iv": "base64",
      "ciphertext": "base64"
    },

    "keyEnvelope": {
      "containerKeyVersion": 1,
      "algorithm": "AES-256-GCM",
      "iv": "base64",
      "ciphertext": "base64"
    }
  }
}
```

---

# 25. Update Conflict

If current revision is no longer:

```text
3
```

return:

```http
409 Conflict
```

```json
{
  "error": {
    "code": "ITEM_CONFLICT",
    "message": "The item changed before this update was applied.",
    "requestId": "uuid"
  }
}
```

Never silently overwrite another device's revision.

---

# 26. Delete Item

```http
DELETE /api/v1/vaults/:vaultId/items/:itemId
```

Requires:

```text
AUTHENTICATED
CSRF
```

Request:

```json
{
  "expectedRevision": 4
}
```

Server creates a tombstone.

Response:

```http
204 No Content
```

---

# 27. Sync

```http
GET /api/v1/sync?after=123
```

Requires:

```text
AUTHENTICATED
```

Response:

```json
{
  "events": [
    {
      "sequence": 124,
      "entityType": "VAULT_ITEM",
      "entityId": "uuid",
      "operation": "UPSERT",
      "revision": 5
    }
  ],

  "cursor": 124
}
```

The client retrieves encrypted entity state as required.

---

# 28. Initial Sync

```http
GET /api/v1/sync/bootstrap
```

Returns:

```json
{
  "sequence": 42,

  "vaults": [],
  "items": []
}
```

All vault contents remain encrypted.

---

# 29. Sessions

## List

```http
GET /api/v1/sessions
```

Response:

```json
{
  "sessions": [
    {
      "id": "uuid",
      "createdAt": "...",
      "lastSeenAt": "...",
      "current": true
    }
  ]
}
```

---

# 30. Revoke Session

```http
DELETE /api/v1/sessions/:sessionId
```

Requires:

```text
AUTHENTICATED
CSRF
```

The current session may revoke another session.

---

# 31. Logout

```http
POST /api/v1/auth/logout
```

Requires:

```text
AUTHENTICATED
CSRF
```

Server revokes session and clears cookie.

Client immediately locks the vault.

---

# 32. Reauthentication

```http
POST /api/v1/auth/reauth/options
```

followed by:

```http
POST /api/v1/auth/reauth/verify
```

Successful verification updates:

```text
session.reauthenticatedAt
```

No extra bearer token is required.

---

# 33. Change Master Password

No dedicated server password-change mechanism exists.

The client:

```text
unlocks ARK
    ↓
derives new MKEK
    ↓
creates new ARK envelope
```

Then:

```http
PUT /api/v1/crypto/password-envelope
```

Requires:

```text
AUTHENTICATED
REAUTHENTICATED
CSRF
```

Request contains:

```json
{
  "kdf": {
    "algorithm": "argon2id",
    "salt": "base64",
    "memoryKiB": 65536,
    "iterations": 3,
    "parallelism": 4
  },

  "rootKeyEnvelope": {
    "keyVersion": 1,
    "algorithm": "AES-256-GCM",
    "iv": "base64",
    "ciphertext": "base64"
  }
}
```

Server never sees old or new Master Password.

---

# 34. Recovery Start

```http
POST /api/v1/recovery/start
```

Request:

```json
{
  "email": "user@example.com"
}
```

Always respond generically:

```http
202 Accepted
```

---

# 35. Recovery Verification

```http
POST /api/v1/recovery/verify-email
```

Returns:

```json
{
  "recoverySession": "short-lived-restricted-token"
}
```

This is not a normal account session.

---

# 36. Recovery Envelope

```http
GET /api/v1/recovery/envelope
```

Requires:

```text
LIMITED_RECOVERY_SESSION
```

Returns encrypted recovery material.

The client decrypts it using its Recovery Kit.

---

# 37. Recovery Completion

```http
POST /api/v1/recovery/complete
```

Client submits:

```text
new password ARK envelope
new recovery envelope
new passkey registration
```

but never:

```text
ARK
Recovery Key
Account Secret
Master Password
```

Existing sessions are revoked.

---

# 38. Audit Events

V1 API does not need a full user-visible audit explorer immediately.

The backend must still generate events for:

```text
ACCOUNT_CREATED

PASSKEY_ADDED
PASSKEY_REMOVED

LOGIN_SUCCESS
LOGIN_FAILURE

SESSION_CREATED
SESSION_REVOKED

ITEM_CREATED
ITEM_UPDATED
ITEM_DELETED

MASTER_PASSWORD_CHANGED

RECOVERY_STARTED
RECOVERY_COMPLETED
```

---

# 39. Request Size Limits

Initial API limits:

```text
JSON body:
    2 MiB

Encrypted item:
    1 MiB

Crypto envelope:
    16 KiB
```

Attachments will use a separate future protocol.

---

# 40. Encoding

Binary values transported through JSON use:

```text
Base64url
```

rather than hexadecimal.

Internally:

```text
Uint8Array / bytes
```

should be preferred over strings for crypto operations.

---

# 41. Time

API timestamps use:

```text
ISO 8601 UTC
```

Example:

```text
2026-09-22T14:30:00.000Z
```

Database uses:

```text
TIMESTAMPTZ
```

---

# 42. API Security Headers

Production should include at minimum:

```text
Strict-Transport-Security
Content-Security-Policy
X-Content-Type-Options
Referrer-Policy
Permissions-Policy
```

The vault application must not allow arbitrary embedding.

---

# 43. API Error Codes

Start with a small stable set:

```text
VALIDATION_ERROR

UNAUTHENTICATED
FORBIDDEN

INVALID_CSRF

INVALID_CHALLENGE
CHALLENGE_EXPIRED

ITEM_NOT_FOUND
ITEM_CONFLICT

VAULT_NOT_FOUND

REAUTHENTICATION_REQUIRED

RECOVERY_INVALID
RECOVERY_EXPIRED

RATE_LIMITED

INTERNAL_ERROR
```

Client logic depends on codes, not English messages.

---

# 44. First Backend Modules

Implement in this order:

```text
config
database
errors
validation
request-context

accounts

webauthn
sessions
csrf

crypto-metadata

vaults
items

sync
audit
```

---

# 45. First Frontend Modules

Implement:

```text
app-shell

registration
passkeys

crypto

auth-state

vault-lock

vault

items
```

Do not build a polished UI yet.

---

# 46. First Crypto-Core Operations

Only implement these initially:

```text
generateAccountSecret()

deriveMasterKey()

deriveMKEK()

generateRootKey()

generateVaultKey()

generateRecoveryKey()

wrapKey()

unwrapKey()

encryptItem()

decryptItem()
```

Nothing else.

No sharing.

No organizations.

No attachments.

---

# 47. First Item Type

Support only:

```text
LOGIN
```

Plaintext client model:

```text
LoginItem {
    name
    username
    password
    urls
    notes
}
```

Entire object is encrypted.

---

# 48. First UI

Only enough UI to prove the system.

Routes:

```text
/register

/login

/unlock

/vault

/vault/new

/security/recovery-kit
```

The first vault screen can be extremely simple.

---

# 49. First Automated Tests

Before considering the slice complete:

### Crypto

```text
correct password + Account Secret
    → ARK decrypts

wrong password
    → decryption fails

wrong Account Secret
    → decryption fails

modified ciphertext
    → authentication fails
```

### Authorization

```text
User A cannot read User B vault.

User A cannot update User B item.

User A cannot delete User B item.
```

### Sessions

```text
invalid session rejected

revoked session rejected

session cookie HttpOnly

CSRF missing → rejected
```

### Vault

```text
create encrypted item
retrieve encrypted item
update revision
conflict rejected
delete tombstone
```

---

# 50. Critical End-to-End Test

The most important initial test:

```text
Create account
     ↓
Generate crypto material
     ↓
Register passkey
     ↓
Store envelopes
     ↓
Create login:
    name = GitHub
    username = test@example.com
    password = CorrectHorseBatteryStaple
     ↓
encrypt
     ↓
store
     ↓
restart client/session
     ↓
authenticate
     ↓
unlock
     ↓
download ciphertext
     ↓
decrypt
```

Expected:

```text
Original item restored.
```

---

# 51. Database Inspection Test

After creating the item, inspect PostgreSQL manually.

Searching the entire database must not reveal:

```text
GitHub
test@example.com
CorrectHorseBatteryStaple
```

This becomes an automated security test later.

---

# 52. First Implementation Milestone

## Milestone M1 — Encrypted Personal Vault

Complete when:

- Monorepo exists
- PostgreSQL runs locally
- Prisma migrations work
- Account registration works
- Email verification can be mocked locally
- Passkey registration works
- Passkey login works
- Opaque sessions work
- CSRF works
- Crypto Core works
- Account Secret is generated
- Recovery Key is generated
- ARK/PVK envelopes work
- Personal vault exists
- Login item can be created
- Login item can be decrypted
- Reload preserves encrypted vault
- Database contains no item plaintext
- Cross-user authorization tests pass

---

# 53. Explicitly Not Part of M1

Do not implement:

```text
Organizations
Sharing
Collections
Teams
RBAC

Browser extension
Autofill

Mobile
Desktop

Attachments

TOTP storage
Passkey storage

Password health

Import / export

Redis

Object storage

Kubernetes

Billing

SSO
SCIM
SIEM
```

We earn those features after the security core works.

---

# 54. Implementation Order

Exact development sequence:

```text
STEP 1
Create monorepo

STEP 2
Create API + health endpoint

STEP 3
Create PostgreSQL + Prisma

STEP 4
Implement users + registration state

STEP 5
Implement WebAuthn registration

STEP 6
Implement opaque sessions

STEP 7
Implement WebAuthn login

STEP 8
Create crypto-core Rust crate

STEP 9
Compile crypto-core to WASM

STEP 10
Implement Account Secret + ARK/PVK generation

STEP 11
Implement crypto bootstrap API

STEP 12
Implement vault persistence

STEP 13
Implement Login item encryption

STEP 14
Implement item APIs

STEP 15
Implement unlock flow

STEP 16
Implement basic sync

STEP 17
Implement Recovery Kit

STEP 18
Implement recovery flow

STEP 19
Security tests

STEP 20
First internal security review
```

---

# 55. First Commit

The first commit should contain only project/bootstrap infrastructure.

Suggested commit:

```text
chore: bootstrap password manager monorepo
```

It should include:

```text
pnpm workspace
React/Vite app
Express API
shared TypeScript config
ESLint
Prettier
Vitest
Docker Compose PostgreSQL
health endpoint
basic CI
```

No authentication yet.

---

# 56. Second Commit

```text
feat: add account persistence and registration flow
```

---

# 57. Third Commit

```text
feat: add passkey authentication and sessions
```

---

# 58. Fourth Commit

```text
feat: add cryptographic account bootstrap
```

---

# 59. Fifth Commit

```text
feat: add encrypted personal vault
```

At this point we should be able to demonstrate the first end-to-end encrypted credential.

---

# 60. Implementation Rule

From this point forward:

> Prefer small, reviewable vertical increments.

Do not implement five security systems in the same commit.

Each milestone should include:

```text
implementation
tests
security assertions
migration
documentation update when protocol changes
```

---

# 61. Protocol Freeze Rule

These documents are now the baseline.

We may change them when implementation reveals problems.

But:

> Code must never silently change the cryptographic protocol.

Any crypto protocol change requires:

```text
document change
+
protocol version consideration
+
test vector update
```

---

# 62. Starting Point

Implementation begins with:

```text
M1.1 — Repository Bootstrap
```

Deliverable:

```text
password-manager/
├── apps/web
├── apps/api
├── packages/*
├── docker-compose.yml
└── CI
```

Then immediately:

```text
M1.2 — PostgreSQL + Prisma foundation
```

No more architecture documents are required before starting.
