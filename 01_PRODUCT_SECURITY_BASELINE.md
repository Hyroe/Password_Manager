# Enterprise Password Manager

## Product & Security Baseline

**Status:** Draft v0.1
**Purpose:** Establish the immutable product and security principles before implementation begins.

---

## 1. Product Vision

Build a professional, zero-knowledge credential management platform suitable for both individuals and enterprise organizations.

The platform must eventually support:

- Passwords
- Secure notes
- TOTP secrets
- API credentials
- SSH credentials
- Payment information
- Identities
- Attachments
- Passkeys
- Shared organizational secrets

The long-term product should operate as a **credential manager**, not only a traditional password manager.

---

## 2. Primary Users

### Individual User

A user can:

- Create an account
- Create and unlock an encrypted vault
- Store credentials
- Organize credentials
- Generate passwords
- Search the local decrypted vault
- Synchronize encrypted data between devices
- Manage trusted devices
- Configure MFA
- Recover the account through explicitly configured recovery mechanisms

### Organization

An organization can eventually:

- Invite and remove members
- Create groups
- Create shared vaults and collections
- Assign permissions
- Enforce security policies
- Configure SSO
- Configure SCIM
- Manage organization devices and sessions
- Inspect audit events
- Recover organization-managed vault access according to configured policies
- Export security events to SIEM platforms

---

## 3. Security Model

The system follows a **zero-knowledge architecture**.

### Fundamental rule

> The server must not possess the cryptographic material required to decrypt user vault contents.

The backend may store:

- Ciphertext
- Encrypted keys
- Public keys
- Cryptographic parameters
- Versions
- Authorization metadata
- Synchronization metadata
- Audit metadata

The backend must not store plaintext:

- Passwords
- Secure notes
- TOTP seeds
- Private SSH keys
- API secrets
- Payment credentials
- Vault encryption keys

---

## 4. Account Authentication != Vault Encryption

Authentication and vault decryption are separate security systems.

### Authentication

Answers:

> Is this user authorized to access this account?

Possible mechanisms:

- Password authentication
- Passkeys
- WebAuthn security keys
- TOTP
- Enterprise SSO

### Vault Unlocking

Answers:

> Does this client possess the key material required to decrypt this vault?

Possible mechanisms:

- Master password-derived key
- Device-protected key
- Recovery key
- Organization recovery mechanism

Authentication success alone must never automatically give the server access to vault plaintext.

---

## 5. Master Password Principle

The master password must never directly encrypt vault items.

Conceptual hierarchy:

```text
Master Password
      │
      ▼
   Argon2id
      │
      ▼
Key Encryption Key (KEK)
      │
      │ decrypts
      ▼
Account Root Key
      │
      ├── Vault Keys
      ├── Collection Keys
      ├── Item Keys
      └── Attachment Keys
```

The Account Root Key must be cryptographically random.

The master password is used to derive key-encryption material, not as the vault encryption key itself.

---

## 6. Security Invariants

These rules are architectural invariants.

### INV-001

The backend cannot decrypt normal user vault contents.

### INV-002

A master password is never stored.

### INV-003

A master password is never logged.

### INV-004

Plaintext vault contents are never logged.

### INV-005

Every encrypted object uses authenticated encryption.

### INV-006

Every cryptographic format is explicitly versioned.

### INV-007

Cryptographic algorithms are never implemented from scratch.

### INV-008

Secrets must not appear in analytics, telemetry, exceptions, audit logs, or traces.

### INV-009

Access to one vault must not provide cryptographic access to unrelated vaults.

### INV-010

Removing organizational access must prevent future decryption of newly rotated organizational material.

### INV-011

Server compromise alone must not reveal user vault plaintext.

### INV-012

Database compromise alone must not reveal user vault plaintext.

### INV-013

Backups must not contain plaintext vault secrets.

### INV-014

Authorization uses deny-by-default semantics.

### INV-015

Security-sensitive state changes must be auditable.

### INV-016

Recovery mechanisms must be explicitly modeled and must never silently introduce a universal decryption backdoor.

---

## 7. Cryptographic Engineering Rules

We will not design our own cryptographic primitives.

Approved implementations must come from mature, reviewed cryptographic libraries.

The cryptographic protocol must define:

- Key generation
- Key derivation
- Key wrapping
- Encryption
- Authentication
- Nonce handling
- Key rotation
- Device keys
- Sharing keys
- Organization keys
- Recovery keys
- Serialization
- Protocol versioning

Before a cryptographic feature is implemented, its protocol must be documented.

---

## 8. Metadata Policy

Vault payloads are not the only sensitive information.

Examples such as:

- `AWS Production`
- `Bank Account`
- `VPN Admin`
- `GitHub Root Token`

can reveal sensitive information even when their passwords remain encrypted.

Therefore metadata will be classified as:

```text
PUBLIC
SERVER_REQUIRED
ENCRYPTED
```

The default classification for credential metadata is:

```text
ENCRYPTED
```

Server-readable metadata must require explicit architectural justification.

---

## 9. Initial Product Scope

The first usable version will intentionally be small.

### V1

Implement:

- Account creation
- Account authentication
- Master password setup
- Cryptographic key hierarchy
- Personal vault
- Login items
- Secure notes
- Custom fields
- Password generator
- Encrypted persistence
- Vault locking/unlocking
- Basic synchronization
- Device/session management
- Recovery key
- Basic security audit events

---

## 10. Explicitly Out of Scope for V1

Do not implement initially:

- Browser autofill
- Mobile applications
- Desktop applications
- Enterprise SSO
- SCIM
- Organization sharing
- Group management
- Enterprise recovery
- SIEM integrations
- Passkey storage
- SSH agent
- Secrets-management CLI
- Kubernetes integration
- Public API
- Billing

These are planned capabilities, not V1 requirements.

---

## 11. Initial Client

The first client will be:

```text
Web Application
```

Its purpose is to validate:

```text
authentication
        +
cryptographic model
        +
vault
        +
sync
```

before distributing the protocol across multiple client implementations.

---

## 12. Backend Architecture

Start with a:

```text
Modular Monolith
```

Not microservices.

Logical modules:

```text
Identity
Vault
Sync
Devices
Organizations
Audit
Notifications
```

Modules must have explicit boundaries so they can later become independent services if required.

---

## 13. Crypto Architecture

Cryptographic operations should be isolated from application/business logic.

Target architecture:

```text
packages/
    crypto-core/
```

The crypto core should expose operations such as:

```text
deriveKey()
generateRootKey()

wrapKey()
unwrapKey()

encryptItem()
decryptItem()

encryptAttachment()
decryptAttachment()

generateKeyPair()

rotateKey()
```

Consumers should not perform low-level cryptographic operations directly.

---

## 14. Security Standards

The engineering process will use, where applicable:

- OWASP ASVS 5.0
- OWASP Cheat Sheet Series
- OWASP Web Security Testing Guide
- NIST SP 800-63-4
- NIST SP 800-63B-4
- WebAuthn
- FIDO2
- RFC-defined cryptographic protocols where applicable

For the core application, the target is high-assurance security equivalent to **OWASP ASVS Level 3 where applicable**.

---

## 15. Enterprise Design Constraint

Even though enterprise functionality will not be built initially, the architecture must not make these features impossible:

```text
Organizations
Groups
Shared Vaults
RBAC
SSO
SCIM
Recovery
Audit
SIEM
Device Management
Security Policies
```

In particular, cryptographic key ownership must anticipate future sharing and organizational access.

---

## 16. What We Will Never Do

We will not:

- Store plaintext vault data server-side
- Send master passwords to analytics systems
- Invent cryptographic algorithms
- Use reversible encryption without authentication
- Hardcode cryptographic keys
- Keep production secrets in source control
- Build a universal server-side vault decryption key
- Log decrypted credentials
- Trust client-provided authorization claims
- Treat JWT possession as sufficient authorization
- Introduce recovery without documenting its cryptographic consequences

---

## 17. Initial Success Criterion

Milestone 1 will be successful when we can demonstrate:

```text
User creates account
        ↓
Client generates cryptographic root material
        ↓
User creates vault item
        ↓
Client encrypts item
        ↓
Server stores ciphertext
        ↓
Database is inspected manually
        ↓
No credential plaintext exists
        ↓
User logs in from another session
        ↓
Client obtains encrypted vault
        ↓
Correct cryptographic material decrypts it
```

The backend must remain incapable of performing that final decryption independently.

---

## 18. Engineering Principle

> No cryptographic feature without a written protocol.

> No protocol change without explicit versioning.

> No sensitive metadata without classification.

> No security assumption left undocumented.
