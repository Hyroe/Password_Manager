**Rory** is a zero-knowledge password manager designed around strong client-side cryptography, passkey authentication, strict trust boundaries, and secure multi-client access.

The project is built as a full-stack security-focused system rather than a traditional CRUD application. Vault secrets are encrypted and decrypted on the client, while the backend stores only ciphertext, encrypted key material, public data required for authentication, and operational metadata.

> **Core security goal:** the server must not possess the cryptographic material required to decrypt a user's vault.

---

## Overview

Rory is designed to provide a secure personal vault for credentials while keeping sensitive plaintext out of the backend, database, logs, telemetry, and server-side application flow.

Current capabilities include:

- Passkey authentication with WebAuthn
- Zero-knowledge client-side vault encryption
- Master Password + Account Secret key hierarchy
- Personal encrypted vault
- Login item creation, update, deletion, restore, and revision history
- Secure vault lock/unlock lifecycle
- Session management and revocation
- Idle and absolute session expiration
- CSRF and strict Origin protection for browser sessions
- Account recovery using a Recovery Kit
- Master Password rotation without re-encrypting every vault item
- Local decrypted search
- Client-side password CSV import
- Encrypted synchronization and incremental change tracking
- Security-focused integration and end-to-end testing
- Browser-extension authentication architecture in progress

---

## Security Architecture

Rory follows a **zero-knowledge architecture**.

```text
             TRUSTED WITH PLAINTEXT
    ─────────────────────────────────────

             Client + Crypto Core
                      │
                      │ encrypted data only
                      ▼
    ─────────────────────────────────────
            NOT TRUSTED WITH PLAINTEXT

              API / PostgreSQL
              Logs / Monitoring
              Analytics / Backups
```

The backend may store:

- Ciphertext
- Encrypted key envelopes
- Public keys
- WebAuthn credentials
- Cryptographic parameters and protocol versions
- Session metadata
- Sync metadata
- Audit/security metadata

The backend must never receive or store:

- Master Passwords
- Recovery Keys
- Plaintext vault credentials
- Unwrapped account or vault keys
- Decrypted vault contents

---

## Key Hierarchy

The cryptographic design separates authentication from vault decryption.

```text
Master Password
      +
Account Secret
      │
      ▼
   Argon2id
      │
      ▼
     MPK
      │
      ▼
     MKEK
      │
      ▼
Encrypted Account Root Key
      │
      ▼
     ARK
      │
      ▼
Encrypted Personal Vault Key
      │
      ▼
     PVK
      │
      ▼
Encrypted Vault Items
```

Authentication alone does **not** unlock the vault.

Rory explicitly distinguishes:

```text
SIGNED_OUT
AUTHENTICATED_LOCKED
UNLOCKED
```

A valid authenticated session proves identity to the server, while vault unlock remains a client-side cryptographic operation.

---

## Authentication

Rory uses **WebAuthn / passkeys** for account authentication.

The web authentication flow uses:

```text
Passkey
   ↓
WebAuthn verification
   ↓
Opaque server-side session
   ↓
HttpOnly cookie
   ↓
CSRF + Origin protection
```

Sessions support:

- Cryptographically random opaque tokens
- Server-side token hashing
- Revocation
- Idle expiration
- Absolute expiration
- Session listing and device metadata
- Sign out current session
- Sign out other sessions

### Browser Extension Sessions

The browser-extension architecture uses a separate authentication transport:

```text
WEB
  session kind: WEB
  transport: HttpOnly cookie
  CSRF protection: required

BROWSER EXTENSION
  session kind: BROWSER_EXTENSION
  transport: Authorization: Bearer <opaque token>
  CSRF cookie flow: not used
```

Session credentials are bound to their intended transport. A web session cannot be reused as a bearer session, and an extension session cannot be reused as a browser cookie session.

---

## Vault Encryption

Vault item plaintext is represented locally as:

```ts
{
  name,
  username,
  password,
  urls,
  notes
}
```

The entire object is encrypted before it crosses the client/server boundary.

```text
Plaintext item
     ↓
Crypto Core
     ↓
Authenticated ciphertext
     ↓
API
     ↓
PostgreSQL
```

The API never needs to understand vault plaintext.

Encrypted formats and key envelopes are explicitly versioned to support protocol evolution and cryptographic agility.

---

## Crypto Core

Security-sensitive cryptographic operations are isolated in a dedicated **Rust cryptographic core compiled to WebAssembly**.

The Crypto Core is responsible for operations such as:

- Key derivation
- Account key generation
- Vault key generation
- Key wrapping and unwrapping
- Item encryption and decryption
- Recovery operations
- Envelope validation
- Protocol/version enforcement

Application code does not directly compose raw cryptographic primitives.

---

## Recovery

Rory supports account recovery without introducing a vendor-controlled universal decryption key.

The Recovery Kit contains client-side recovery material and is required together with the recovery flow to restore access to the account key hierarchy.

Recovery:

- Replaces the password-derived root-key envelope
- Rotates recovery state
- Revokes existing sessions
- Preserves encrypted vault items
- Does not require item-by-item re-encryption

The Recovery Kit is not uploaded to the backend as plaintext recovery material.

---

## Password Import

Credential imports are handled client-side.

```text
Browser CSV export
       ↓
Local parser
       ↓
Normalize credential
       ↓
Existing Crypto Core
       ↓
Ciphertext
       ↓
API
```

Security properties:

- Raw CSV is not sent to the server
- Imported passwords are not logged
- Import requires an unlocked vault
- Plaintext import data is kept short-lived
- Field and row limits are enforced
- Imported credentials reuse the normal encrypted item creation path

---

## Browser Extension

A Chromium browser extension is currently being developed.

The extension is designed as its **own security boundary** while reusing Rory's protocol and cryptographic core.

Planned architecture:

```text
User opens Rory extension
        ↓
Identify active tab origin
        ↓
Find compatible credentials locally
        ↓
User selects credential
        ↓
Inject only selected username/password
        ↓
Fill login form
```

Initial design principles:

- Chromium Manifest V3
- `activeTab` instead of broad permanent page access
- `scripting.executeScript()` for explicit manual fill
- No `<all_urls>` permission for the initial MVP
- No persistent decrypted vault
- No Master Password in browser storage
- No ARK/PVK in `storage.local`
- Extension-specific WebAuthn login
- Extension-specific bearer sessions
- Exact origin/domain matching
- Hostile DOM and phishing defenses
- Firefox compatibility planned after Chromium hardening

---

## Threat Model

The project is developed against an explicit threat model.

Important threat classes include:

- XSS
- CSRF
- Session theft and replay
- Cross-user authorization failures
- Malicious browser extensions
- Message spoofing
- Excessive extension permissions
- Autofill attacks
- Phishing
- Compromised origins
- Plaintext leakage through logs or telemetry
- Malicious import files
- Database compromise
- Stolen encrypted backups

High-risk components receive additional review, including:

- Crypto Core
- Authentication
- Recovery
- Browser Extension
- Autofill Engine
- Sync Protocol
- Import / Export

---

## Technology Stack

### Frontend

- React
- TypeScript
- Vite
- Material UI
- WebAssembly

### Backend

- Node.js
- TypeScript
- Express
- Zod

### Database

- PostgreSQL
- Prisma

### Cryptography

- Rust
- WebAssembly
- Argon2id
- Authenticated encryption
- Versioned key envelopes

### Authentication

- WebAuthn
- Passkeys
- Opaque server-side sessions

### Testing

- Vitest
- Supertest
- Playwright

### Infrastructure

- pnpm workspaces
- Docker
- Docker Compose
- GitHub Actions

---

## Repository Structure

```text
password-manager/
│
├── apps/
│   ├── web/
│   ├── api/
│   └── browser-extension/        # in development
│
├── packages/
│   ├── crypto-core/
│   ├── protocol/
│   ├── schemas/
│   ├── client-sdk/
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
├── tests/
├── docker-compose.yml
├── pnpm-workspace.yaml
└── package.json
```

Some directories may evolve as the browser-extension work is integrated.

---

## Testing Strategy

Security properties are tested at multiple layers.

### Integration Tests

Backend tests cover areas such as:

- Authentication
- Session lifecycle
- Session revocation
- Client-kind / transport binding
- CSRF
- Origin validation
- Challenge replay protection
- Cross-user authorization
- Encrypted vault item lifecycle
- Revision conflicts
- Tombstones and restore
- Incremental synchronization
- Pagination and cursor validation

### End-to-End Tests

Playwright exercises the real browser flow including:

```text
Register
   ↓
Verify email
   ↓
Create passkey
   ↓
Initialize cryptographic account
   ↓
Authenticate
   ↓
Unlock vault
   ↓
Create encrypted credential
   ↓
Update / delete / restore
   ↓
Reload
   ↓
Unlock again
   ↓
Decrypt original data
```

The E2E suite also verifies that plaintext vault fields do not appear in API mutation bodies.

---

## Security Invariants

The project treats the following as non-negotiable invariants:

1. The backend cannot decrypt the user's personal vault.
2. The Master Password is never stored server-side.
3. Vault plaintext is never written to logs, traces, analytics, or audit records.
4. Authentication and vault unlock are separate security states.
5. Every persistent encrypted format is versioned.
6. Authenticated encryption is required for encrypted objects.
7. Session tokens are opaque and stored server-side only as hashes.
8. Browser cookie sessions require CSRF and Origin protection.
9. Authentication transports are explicitly bound to their client type.
10. Browser storage must not persist decrypted vault contents or unwrapped vault keys.
11. Security-sensitive changes must fail closed.
12. Cryptographic primitives are provided by vetted libraries rather than custom algorithms.

---

## Local Development

### Requirements

Install:

- Node.js
- pnpm
- PostgreSQL or Docker
- Rust
- `wasm-pack`

### Install dependencies

```bash
pnpm install
```

### Start infrastructure

```bash
docker compose up -d
```

### Generate Prisma client

```bash
pnpm --filter @pm/api db:generate
```

### Apply database migrations

Use the Prisma migration workflow configured by the API package.

For local development:

```bash
pnpm --filter @pm/api exec prisma migrate dev
```

Test databases must also be migrated before running integration tests.

### Run API tests

```bash
pnpm --filter @pm/api test
```

### Type checking

```bash
pnpm --filter @pm/api typecheck
```

Additional workspace scripts are available in the repository package manifests.

---

## Development Philosophy

Rory is developed in small, reviewable increments.

Security-sensitive changes generally follow:

```text
Design
  ↓
Threat analysis
  ↓
Implementation
  ↓
Integration tests
  ↓
Adversarial tests
  ↓
Manual verification where needed
  ↓
Commit
```

Broad refactors are intentionally kept separate from cryptographic or authentication protocol changes.

---

## Project Status

Rory is under active development.

### Implemented

- Zero-knowledge personal vault architecture
- Passkey authentication
- Client-side cryptographic bootstrap
- Master Password + Account Secret key hierarchy
- Encrypted credential storage
- Immutable item revisions
- Vault synchronization
- Lock/unlock lifecycle
- Session management
- CSRF and Origin protection
- Master Password change
- Account recovery
- Client-side password import
- Security and E2E test coverage
- Web UI for authentication, vault, recovery, and security management
- Web/extension session transport separation

### In Progress

- Chromium browser extension
- Extension-specific WebAuthn authentication
- Origin-based credential matching
- Manual form filling
- Hostile-page hardening

### Planned

- Autofill hardening
- Trusted/persistent extension unlock model
- Firefox compatibility
- Additional item types
- Broader enterprise capabilities

---

## Security Notice

Rory is a security-focused project under active development and should not be treated as production-ready until its cryptographic design, extension boundary, deployment model, and release pipeline have completed the intended security review.

Do not use development builds to store credentials you cannot afford to lose.

---

## Why This Project Exists

Password managers sit at the intersection of application security, cryptography, authentication, browser security, distributed state, and usability.

Rory is being built to explore that intersection with explicit security boundaries rather than treating encryption as an implementation detail.

The goal is not merely to store passwords.

The goal is to build a system in which the architecture itself limits who is capable of seeing them.
