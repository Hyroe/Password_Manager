# Enterprise Password Manager

## System Architecture

**Status:** Draft v0.1
**Architecture Style:** Modular Monolith + Client-Side Cryptography
**Security Model:** Zero-Knowledge
**Primary Client:** Web Application

---

# 1. Objective

Define the first production-capable system architecture for the password manager.

The architecture must preserve:

```text
Client owns plaintext and cryptographic secrets.

Server owns:
    identity
    authorization
    encrypted persistence
    synchronization
    audit metadata
```

The server must never become the location where vault plaintext is processed.

---

# 2. High-Level Architecture

```text
┌──────────────────────────────────────┐
│             WEB CLIENT               │
│                                      │
│  React / TypeScript                  │
│                                      │
│  ┌────────────────────────────────┐  │
│  │ Crypto Core                    │  │
│  │                                │  │
│  │ Key derivation                 │  │
│  │ Encryption / Decryption        │  │
│  │ Key wrapping                   │  │
│  │ Recovery                       │  │
│  └────────────────────────────────┘  │
│                                      │
│  Vault State                         │
│  Sync Client                         │
│  Auth Client                         │
└──────────────────┬───────────────────┘
                   │
                   │ HTTPS
                   │ ciphertext only
                   ▼
┌──────────────────────────────────────┐
│                API                   │
│                                      │
│  Identity                            │
│  Sessions                            │
│  Vault                               │
│  Sync                                │
│  Devices                             │
│  Recovery Metadata                   │
│  Audit                               │
│  Organizations                      │
└───────────────┬──────────────────────┘
                │
       ┌────────┼─────────┐
       │        │         │
       ▼        ▼         ▼
 PostgreSQL   Redis    Object Storage
       │
       ▼
 Encrypted Backups

Infrastructure secrets:
        │
        ▼
       KMS
```

---

# 3. Core Architectural Rule

The most important boundary is:

```text
       TRUSTED WITH PLAINTEXT
────────────────────────────────
Client + Crypto Core


       NOT TRUSTED WITH PLAINTEXT
────────────────────────────────
API
Database
Redis
Object Storage
Queues
Logs
Monitoring
Analytics
Backups
Support systems
```

---

# 4. Architecture Strategy

We will begin with a:

```text
Modular Monolith
```

rather than microservices.

Reasons:

- Easier transactional consistency
- Easier development
- Less operational complexity
- Easier security review
- Easier local development
- Easier integration testing
- Smaller infrastructure attack surface

Logical boundaries will still be strict enough to allow future extraction.

---

# 5. Monorepo

Initial structure:

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
│   ├── client-sdk/
│   └── shared-types/
│
├── infrastructure/
│   ├── docker/
│   ├── terraform/
│   └── environments/
│
├── security/
│   ├── 01_PRODUCT_SECURITY_BASELINE.md
│   ├── 02_THREAT_MODEL.md
│   ├── 03_CRYPTOGRAPHIC_ARCHITECTURE.md
│   ├── 04_KEY_HIERARCHY_AND_LIFECYCLE.md
│   └── 05_SYSTEM_ARCHITECTURE.md
│
├── docs/
│
├── scripts/
│
└── tests/
```

---

# 6. Technology Direction

Initial candidate stack:

```text
Frontend
    React
    TypeScript
    Vite

Backend
    Node.js
    TypeScript
    Fastify or Express

Database
    PostgreSQL

ORM
    Prisma or equivalent

Validation
    Zod

Cache / short-lived coordination
    Redis

Object Storage
    S3-compatible storage

Crypto Core
    Rust
    WASM bindings for Web

Infrastructure
    Docker
    Terraform

CI/CD
    GitHub Actions
```

These choices are implementation candidates, not cryptographic protocol requirements.

---

# 7. Web Client Responsibilities

The Web Client owns:

```text
Master Password handling
Account Secret handling
Argon2id execution
ARK unlocking
Vault key unlocking
Item encryption
Item decryption
Recovery operations
Password generation
Local search
Plaintext rendering
```

The backend must not perform these operations.

---

# 8. Web Client Modules

Suggested structure:

```text
apps/web/src/
│
├── auth/
├── vault/
├── crypto/
├── sync/
├── session/
├── recovery/
├── settings/
├── components/
└── routes/
```

Crypto implementation itself does not live here.

Instead:

```text
packages/crypto-core
```

provides controlled operations.

---

# 9. Crypto Core

Crypto Core is one of the highest-security components.

Responsibilities:

```text
generateAccountSecrets()
deriveMasterKey()
deriveMKEK()

generateARK()
generateVaultKey()
generateItemKey()

wrapKey()
unwrapKey()

encryptItem()
decryptItem()

createRecoveryEnvelope()
recoverARK()

validateEnvelope()
migrateEnvelope()
```

Business logic must never directly invoke raw primitives.

---

# 10. Crypto Core Boundary

Preferred architecture:

```text
Rust
   ↓
compiled to
   ↓
WASM
   ↓
Web Client
```

Future clients may reuse the same Rust implementation:

```text
Rust Core
 ├── WASM
 ├── Desktop
 ├── iOS bindings
 └── Android bindings
```

This avoids implementing the cryptographic protocol independently in several languages.

---

# 11. Protocol Package

`packages/protocol/` defines structures shared across client and server.

Examples:

```text
CryptoEnvelope
VaultRecord
ItemRecord
KeyEnvelope
SyncRevision
RecoveryEnvelope
DeviceRecord
```

Important rule:

> Protocol definitions may describe ciphertext but must not contain cryptographic implementation logic.

---

# 12. Shared Schemas

`packages/schemas/` contains validated wire schemas.

Example:

```text
CreateEncryptedItemRequest
UpdateEncryptedItemRequest
SyncRequest
SyncResponse
CreateSessionRequest
RecoveryMetadataResponse
```

All external API input must be validated.

---

# 13. Backend Modules

Initial backend:

```text
apps/api/src/modules/
│
├── identity/
├── sessions/
├── vaults/
├── sync/
├── devices/
├── recovery/
├── audit/
└── organizations/
```

V1 implementation focuses primarily on:

```text
identity
sessions
vaults
sync
recovery
audit
```

---

# 14. Identity Module

Responsibilities:

```text
Account creation
Authentication
Email verification
Authentication factors
Account state
Passkeys eventually
MFA eventually
```

Identity is not responsible for vault decryption.

---

# 15. Sessions Module

Responsibilities:

```text
Create session
Rotate session
Refresh session
Revoke session
List active sessions
Terminate device sessions
```

Session state must remain separate from vault unlock state.

Server knows:

```text
AUTHENTICATED
```

Server does not know:

```text
VAULT UNLOCKED
```

unless the client explicitly reports non-sensitive state for UX purposes.

---

# 16. Vault Module

The Vault Module handles encrypted objects.

Responsibilities:

```text
Create encrypted vault
Store encrypted key envelopes
Store encrypted items
Update encrypted items
Delete items
Revision validation
Ownership enforcement
```

It does not:

```text
decrypt items
inspect password fields
search plaintext
classify secrets
```

---

# 17. Vault Data Flow

Creating an item:

```text
User enters credential
        ↓
Web Client
        ↓
Crypto Core
        ↓
Encrypted payload
Wrapped Item Key
        ↓
API
        ↓
Authorization
        ↓
PostgreSQL
```

At no point after the client boundary should plaintext exist.

---

# 18. Reading an Item

```text
Web Client
    ↓
API request
    ↓
Authorization
    ↓
Database
    ↓
Encrypted item
    ↓
Web Client
    ↓
Crypto Core
    ↓
Plaintext
```

The decryption step occurs only after the response returns to the client.

---

# 19. Sync Module

Sync is responsible for distributing encrypted state across devices.

Responsibilities:

```text
Incremental synchronization
Revision tracking
Tombstones
Conflict detection
Cursor management
Idempotency
```

It should not understand vault plaintext.

---

# 20. Initial Sync Model

Each account maintains a monotonically increasing server revision.

Example:

```text
revision 100
revision 101
revision 102
```

Every mutation increments the revision.

Client stores:

```text
lastSeenRevision
```

Then:

```text
GET /sync?after=102
```

could return:

```text
revision 103 → item changed
revision 104 → item deleted
revision 105 → key envelope changed
```

---

# 21. Sync Record

Conceptually:

```json
{
  "revision": 105,
  "entityType": "vault_item",
  "entityId": "uuid",
  "operation": "UPSERT",
  "updatedAt": "...",
  "payload": {
    "ciphertext": "...",
    "keyEnvelope": "..."
  }
}
```

Server revisions are synchronization metadata.

They do not replace cryptographic revision metadata.

---

# 22. Optimistic Concurrency

Updates must include:

```text
expectedRevision
```

Example:

```text
Client has item revision 4

PATCH item
expectedRevision = 4
```

If database already contains revision 5:

```text
409 Conflict
```

The client resolves the conflict explicitly.

Silent last-write-wins should not be the default for secrets.

---

# 23. Recovery Module

Server responsibilities:

```text
Store encrypted recovery envelope
Store recovery metadata
Authorize recovery workflow
Rate-limit recovery operations
Audit recovery attempts
```

Server must never receive:

```text
Recovery Key
Account Secret
ARK
```

in plaintext.

---

# 24. Audit Module

Audit stores security events.

Examples:

```text
ACCOUNT_CREATED
LOGIN_SUCCESS
LOGIN_FAILURE
SESSION_CREATED
SESSION_REVOKED

DEVICE_REGISTERED
DEVICE_REVOKED

VAULT_CREATED

ITEM_CREATED
ITEM_UPDATED
ITEM_DELETED

RECOVERY_STARTED
RECOVERY_COMPLETED

PASSWORD_CHANGED
```

Audit records must contain identifiers, not secrets.

---

# 25. Audit Example

Safe:

```json
{
  "event": "ITEM_UPDATED",
  "actorId": "user_uuid",
  "itemId": "item_uuid",
  "timestamp": "...",
  "requestId": "..."
}
```

Unsafe:

```json
{
  "event": "ITEM_UPDATED",
  "itemName": "AWS Production",
  "username": "root",
  "password": "..."
}
```

---

# 26. PostgreSQL Responsibilities

PostgreSQL stores:

```text
Users
Authentication identities
Sessions
Devices

Vault metadata
Encrypted vault keys
Encrypted item keys
Encrypted item payloads
Recovery envelopes

Sync revisions
Audit events

Organizations later
Membership later
```

---

# 27. PostgreSQL Must Never Store

```text
Master Password
Account Secret
MPK
MKEK
ARK
PVK
IK
Recovery Key
Plaintext vault items
Plaintext attachments
```

---

# 28. Redis Responsibilities

Redis may be used for:

```text
Rate limiting
Temporary authentication challenges
Passkey challenges
Distributed locks
Idempotency keys
Short-lived coordination
```

Redis must not contain:

```text
Vault plaintext
ARK
PVK
Item Keys
Recovery Keys
```

---

# 29. Redis Policy

Everything in Redis must be considered:

```text
temporary
reconstructable
non-authoritative
```

The system must remain correct after Redis data loss.

---

# 30. Object Storage

Used later for encrypted attachments.

Object storage receives:

```text
Encrypted attachment blob
```

not:

```text
plaintext file
```

Upload flow:

```text
Client
   ↓ encrypt
Ciphertext
   ↓
Object Storage
```

Prefer direct encrypted uploads through limited pre-signed URLs.

---

# 31. KMS

Cloud KMS protects infrastructure secrets.

Examples:

```text
Session signing keys
Service credentials
Database encryption keys
Webhook secrets
Email provider credentials
```

KMS does NOT hold:

```text
ARK
PVK
IK
PRK
user vault master key
```

This distinction is critical.

---

# 32. Infrastructure Encryption vs Vault Encryption

These are independent layers.

```text
Disk Encryption
Database Encryption
Backup Encryption
         +
Application Zero-Knowledge Encryption
```

Infrastructure encryption protects physical/cloud storage exposure.

Application encryption protects against backend and database compromise.

We require both.

---

# 33. API Trust Boundary

Every API request must pass:

```text
Transport Security
      ↓
Authentication
      ↓
Schema Validation
      ↓
Authorization
      ↓
Business Rules
      ↓
Persistence
```

Never:

```text
Controller
   ↓
database query using arbitrary user identifier
```

---

# 34. Authorization

Authorization must be resource-based.

Example:

```text
request user
      ↓
vault ownership
      ↓
item membership
      ↓
permission
```

Never trust:

```text
userId
organizationId
role
ownerId
```

supplied by the client.

Authoritative identity comes from the authenticated session.

---

# 35. API Identifiers

Use opaque identifiers.

Example:

```text
UUIDv7
```

or equivalent.

Identifiers are not authorization mechanisms.

Knowing:

```text
itemId
```

must provide zero authorization.

---

# 36. Request IDs

Every incoming request receives:

```text
requestId
```

used across:

```text
logs
audit
metrics
errors
traces
```

Request IDs must not encode user secrets.

---

# 37. Error Handling

Production errors must not expose:

```text
SQL
stack traces
filesystem paths
key material
ciphertext internals
security configuration
```

External:

```json
{
  "error": {
    "code": "ITEM_CONFLICT",
    "requestId": "..."
  }
}
```

Internal logs may contain technical details after redaction.

---

# 38. Logging Architecture

Structured logs only.

Example:

```json
{
  "level": "info",
  "event": "session.created",
  "userId": "...",
  "requestId": "...",
  "timestamp": "..."
}
```

Prohibited:

```text
raw request bodies
authorization headers
cookies
vault payloads
crypto keys
recovery material
```

---

# 39. Observability

We need:

```text
Metrics
Logs
Tracing
Security events
Alerts
```

Metrics may include:

```text
API latency
DB latency
error rates
login failures
rate-limit events
sync conflicts
KDF duration client-side
```

Never secrets.

---

# 40. Frontend Logging

Sensitive client areas should have minimal telemetry.

No analytics provider should receive:

```text
vault item names
URLs
usernames
password lengths
clipboard contents
search queries
decrypted fields
```

---

# 41. Domain Separation

Eventually separate public website and vault application.

Example:

```text
www.example.com
```

Marketing site.

```text
vault.example.com
```

Authenticated vault application.

Reasons:

```text
smaller script surface
stronger CSP
less third-party code
reduced XSS exposure
cleaner cookie boundaries
```

---

# 42. Content Security Policy

The vault frontend should target a strict CSP.

Goals:

```text
No arbitrary third-party scripts
No unsafe-inline
No eval
Restricted connect-src
Restricted frame-src
Restricted object-src
```

The authenticated vault must have a significantly smaller trust surface than the marketing site.

---

# 43. Authentication Cookies

If cookie-backed sessions are used:

```text
HttpOnly
Secure
SameSite
```

Session credentials must not be accessible to regular JavaScript unless architecture explicitly requires it.

Vault encryption keys remain independent from session cookies.

---

# 44. CSRF

Cookie-authenticated state-changing endpoints require appropriate CSRF defenses.

Potential layers:

```text
SameSite
Origin verification
CSRF tokens
restricted content types
```

Final strategy depends on the chosen session architecture.

---

# 45. Session Architecture

Preferred direction:

```text
Opaque server-managed sessions
```

rather than putting extensive authorization state into long-lived JWTs.

Conceptually:

```text
Secure HttpOnly session cookie
           ↓
random opaque session ID
           ↓
server-side session record
```

Benefits:

```text
immediate revocation
device tracking
risk metadata
permission changes
simpler invalidation
```

---

# 46. Authentication State vs Vault State

Frontend state machine:

```text
SIGNED_OUT
    ↓
AUTHENTICATED_LOCKED
    ↓
UNLOCKED
```

Example:

```text
User session valid
+
ARK absent
=
AUTHENTICATED_LOCKED
```

This is a fundamental application concept.

---

# 47. Auto-Lock

Client owns vault auto-lock.

Potential triggers:

```text
Idle timeout
Browser close
Explicit lock
Session expiration
Security event
Account change
Memory pressure/security condition
```

Locking means cryptographic material is removed from active application state.

---

# 48. Local Web Storage

V1 web policy:

May persist:

```text
Encrypted records
Sync cursor
Non-sensitive preferences
Protocol versions
```

Must not persist:

```text
Master Password
MPK
MKEK
Plaintext ARK
Plaintext vault
Recovery Key
```

Use IndexedDB rather than localStorage for structured encrypted caches when required.

---

# 49. Service Workers

Service Workers are high-risk because they can persist and intercept application traffic.

Initial recommendation:

```text
Do not use a service worker for the vault application in V1
```

unless required and separately threat-modeled.

---

# 50. API Architecture

Initial routes conceptually:

```text
/api/v1/auth/*
/api/v1/sessions/*
/api/v1/accounts/*
/api/v1/vaults/*
/api/v1/items/*
/api/v1/sync/*
/api/v1/recovery/*
/api/v1/devices/*
/api/v1/audit/*
```

API versioning starts immediately.

---

# 51. Example Account Bootstrap

```text
POST /api/v1/accounts
```

Client sends:

```text
identity information
authentication registration material
KDF configuration
wrapped ARK
wrapped PVK
recovery envelope
public protocol metadata
```

Client does not send:

```text
Master Password
Account Secret
ARK
PVK
Recovery Key
```

---

# 52. Example Vault Item Creation

```text
POST /api/v1/vaults/{vaultId}/items
```

Request:

```json
{
  "id": "uuid",
  "protocolVersion": 1,
  "revision": 1,
  "keyEnvelope": {
    "keyVersion": 1,
    "algorithm": "AES-256-GCM",
    "iv": "...",
    "ciphertext": "..."
  },
  "payload": {
    "algorithm": "AES-256-GCM",
    "iv": "...",
    "ciphertext": "..."
  }
}
```

No plaintext item properties exist in the request.

---

# 53. Sync API

Initial conceptual endpoint:

```text
GET /api/v1/sync?cursor=...
```

Returns:

```text
encrypted mutations
tombstones
new key envelopes
latest cursor
```

Later we may prefer a single sync endpoint over many individual item fetches for client efficiency.

---

# 54. Transaction Boundaries

Operations such as:

```text
create item
update item
delete item
rotate envelope
increment sync revision
write audit event
```

should be transactional where practical.

Example:

```text
BEGIN

update item
increment account revision
create sync event
create audit event

COMMIT
```

---

# 55. Outbox Pattern

Eventually external side effects should use a transactional outbox.

Example:

```text
DB transaction
   ├── update session
   ├── write audit event
   └── insert notification outbox

worker
   ↓
send security notification
```

This avoids sending email while a database transaction may still fail.

---

# 56. Background Workers

Potential future jobs:

```text
Email notifications
Audit export
Tombstone cleanup
Attachment cleanup
Account deletion
Key migration coordination
Security alerts
```

Workers must not decrypt vault data.

---

# 57. Queues

If queues are introduced:

Safe:

```text
userId
eventId
itemId
notification type
audit event
```

Unsafe:

```text
plaintext credential
master password
vault key
decrypted attachment
```

---

# 58. Database Connections

Use separate privileges for:

```text
application
migrations
administration
backup
```

The running application should not have schema-owner privileges.

---

# 59. Database Migrations

Migrations:

```text
version controlled
reviewed
tested against production-like data
backward-compatible where necessary
```

Security-sensitive schema changes require explicit review.

---

# 60. Availability Architecture

Initial deployment may use:

```text
Load Balancer
      ↓
2+ stateless API instances
      ↓
PostgreSQL
Redis
Object Storage
```

The API must remain horizontally scalable.

Do not depend on process-local session state.

---

# 61. Stateless API

Persist authoritative state externally.

Do not rely on:

```text
server memory session
local disk
single process locks
```

for correctness.

---

# 62. Multi-Region

Not required for V1.

But IDs, clocks, revisions, and storage should not make future regional deployment impossible.

Initial recommendation:

```text
single primary region
multi-AZ infrastructure
```

before introducing multi-region consistency complexity.

---

# 63. Backups

Required from the first production deployment:

```text
Automated backups
Encrypted backups
Point-in-time recovery
Restore testing
Retention policy
Access auditing
```

A backup is not considered valid until restore has been tested.

---

# 64. Disaster Recovery

Document:

```text
RPO
RTO
database restore
object storage restore
KMS dependencies
DNS failover
session invalidation
security-state reconciliation
```

Exact objectives depend on product maturity.

---

# 65. Infrastructure Environments

At minimum:

```text
local
development
staging
production
```

Production credentials must never be available in development environments.

Production datasets must not be copied into development without explicit sanitization.

---

# 66. Developer Access

Principle:

```text
No engineer should need routine direct production DB access.
```

When exceptional access is required:

```text
time-limited
approved
audited
least privilege
```

---

# 67. Support Access

Support agents must not have:

```text
vault plaintext
encryption keys
recovery secrets
```

Admin tooling should expose only operational metadata necessary for support.

---

# 68. Secret Management

Infrastructure secrets live in:

```text
KMS / Secret Manager
```

not:

```text
Git
Docker images
source files
frontend bundles
long-lived plaintext .env files in production
```

---

# 69. CI/CD Trust Boundary

CI/CD can modify shipped application code and is therefore a critical security component.

Protect with:

```text
Branch protection
Required review
Minimal workflow permissions
Pinned actions
OIDC cloud authentication
No long-lived deployment keys
Artifact signing
Dependency scanning
Secret scanning
```

---

# 70. Build Separation

Prefer:

```text
build
    ↓
immutable artifact
    ↓
security checks
    ↓
promotion
```

over rebuilding separate source for every environment.

Production should run the reviewed artifact.

---

# 71. Client Release Security

For future native clients:

```text
signed releases
verified updates
release provenance
rollback protection where possible
```

Browser extension releases also require strict signing/store controls.

---

# 72. Security Critical Packages

Code ownership should eventually require explicit review for:

```text
packages/crypto-core
auth
sessions
recovery
sync
authorization
browser-extension
```

Not every developer should be able to merge security-critical modifications unreviewed.

---

# 73. Testing Layers

Architecture must support:

```text
Unit tests
Integration tests
Crypto vectors
Database tests
API tests
Authorization tests
Sync tests
Browser tests
Security tests
Fuzzing
```

---

# 74. Local Development

Docker Compose may initially provide:

```text
PostgreSQL
Redis
S3-compatible storage
API
```

Web client may run separately through Vite.

No production secret should be needed for local development.

---

# 75. Future Organization Architecture

Organizations remain inside the modular monolith initially.

```text
organizations/
    members
    groups
    collections
    policies
```

Do not create an independent organization microservice prematurely.

---

# 76. Future Browser Extension

Browser extension should use the same:

```text
Crypto Core
Protocol
Client SDK
```

but have its own security boundary.

It should not simply embed the full web vault into arbitrary pages.

---

# 77. Future Native Clients

Expected:

```text
Desktop
iOS
Android
```

All should speak the same versioned protocol.

Server behavior must not depend on client-specific plaintext semantics.

---

# 78. Public API

Enterprise API access is future scope.

Public API must primarily operate on:

```text
administrative metadata
encrypted vault objects
organization management
audit
```

Server-side plaintext credential APIs would conflict with zero-knowledge design and require separate product/security architecture.

---

# 79. Critical Data Flow Summary

## Account creation

```text
Browser
 ↓
Crypto Core generates secrets
 ↓
Browser encrypts key hierarchy
 ↓
API receives envelopes
 ↓
PostgreSQL
```

## Unlock

```text
API
 ↓
encrypted envelopes
 ↓
Browser
 ↓
Crypto Core
 ↓
ARK exists only client-side
```

## Item write

```text
Plaintext
 ↓
Crypto Core
 ↓
ciphertext
 ↓
API
 ↓
Database
```

## Item read

```text
Database
 ↓
ciphertext
 ↓
API
 ↓
Browser
 ↓
Crypto Core
 ↓
Plaintext
```

---

# 80. Failure Domain Principle

Every subsystem should fail independently where possible.

Example:

```text
Redis lost
    ≠
vault lost

API instance lost
    ≠
session database lost

Object storage unavailable
    ≠
password vault unavailable

Analytics unavailable
    ≠
authentication unavailable
```

---

# 81. Architecture Invariants

### SYS-001

Only clients decrypt vault contents.

### SYS-002

Backend never requires vault plaintext for normal operation.

### SYS-003

Crypto Core is the only module performing low-level cryptographic operations.

### SYS-004

Authentication state and unlock state are separate.

### SYS-005

Authorization is always server-side.

### SYS-006

Opaque IDs never imply authorization.

### SYS-007

Redis is never authoritative.

### SYS-008

Object storage contains encrypted blobs only.

### SYS-009

KMS protects infrastructure secrets, not user vault master keys.

### SYS-010

Logs, traces, metrics, analytics, and audit events must never contain vault secrets.

### SYS-011

All persistent encrypted formats are versioned.

### SYS-012

Sync must detect conflicts rather than silently overwriting secrets.

### SYS-013

All production changes pass through controlled CI/CD.

### SYS-014

No normal operational workflow requires employee access to vault plaintext.

---

# 82. V1 Deployment Shape

A realistic first deployment:

```text
                     Internet
                        │
                        ▼
                  CDN / WAF
                        │
              ┌─────────┴─────────┐
              │                   │
              ▼                   ▼
         Static Web           Load Balancer
                                  │
                           ┌──────┴──────┐
                           ▼             ▼
                         API 1         API 2
                           │             │
                           └──────┬──────┘
                                  │
                    ┌─────────────┼─────────────┐
                    ▼             ▼             ▼
                PostgreSQL      Redis      Object Storage
                    │
                    ▼
                  Backup

Infrastructure secrets
        │
        ▼
       KMS
```

---

# 83. What We Do Not Need Yet

Do not introduce yet:

```text
Kubernetes
Kafka
multiple microservices
service mesh
multi-region writes
event sourcing everywhere
GraphQL federation
custom distributed databases
```

Security does not come from infrastructure complexity.

---

# 84. First Implementation Boundary

Before building the entire product, create one vertical slice:

```text
Register Account
      ↓
Generate Crypto Material
      ↓
Store Encrypted Root Envelopes
      ↓
Authenticate
      ↓
Unlock Vault
      ↓
Create One Login Item
      ↓
Encrypt Client-Side
      ↓
Persist Ciphertext
      ↓
Reload
      ↓
Decrypt Client-Side
```

If this flow is architecturally clean, the rest of V1 can grow around it.

---

# 85. Next Artifact

Next:

```text
06_DATABASE_SCHEMA.md
```

It will define the first real persistence model:

```text
User
AuthenticationIdentity
Session
Device

Vault
VaultKeyEnvelope

VaultItem
ItemKeyEnvelope
ItemRevision

RecoveryEnvelope

SyncRevision
SyncEvent

AuditEvent
```

For every field we will explicitly classify:

```text
PLAINTEXT_SERVER_METADATA
CIPHERTEXT
PUBLIC_CRYPTO_MATERIAL
SECURITY_SENSITIVE_METADATA
```

The database schema must make it structurally difficult to accidentally store plaintext vault content.
