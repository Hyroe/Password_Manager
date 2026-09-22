# Enterprise Password Manager

## Database Schema

**Status:** Draft v0.1
**Database:** PostgreSQL
**Architecture:** Zero-Knowledge / Modular Monolith
**Scope:** V1 persistence model

---

# 1. Objective

Design the initial PostgreSQL schema while preserving the core rule:

> The database stores encrypted vault state, never vault plaintext.

The schema must support:

- Accounts
- Authentication identities
- Sessions
- Devices
- User cryptographic configuration
- Personal vaults
- Wrapped vault keys
- Encrypted items
- Item key envelopes
- Recovery
- Synchronization
- Audit events

Future organizations and sharing must remain possible without redesigning the V1 core.

---

# 2. Data Classification

Every database field belongs to one of four classes.

```text
SERVER_METADATA
```

Data required by the backend for normal operation.

Examples:

- IDs
- timestamps
- revisions
- account status

---

```text
SECURITY_METADATA
```

Sensitive but necessarily server-readable.

Examples:

- email
- IP address
- authentication state
- device metadata
- KDF parameters

Requires:

- strict authorization
- limited retention
- logging controls

---

```text
PUBLIC_CRYPTO
```

Cryptographic material that is safe to expose.

Examples:

- salts
- public keys
- IVs/nonces
- algorithm identifiers
- protocol versions

---

```text
CIPHERTEXT
```

Opaque encrypted material.

Examples:

- wrapped ARK
- wrapped PVK
- wrapped IK
- encrypted item payload

The backend must not attempt to interpret it.

---

# 3. V1 Entity Overview

```text
User
 │
 ├── AuthenticationIdentity
 ├── Session
 ├── Device
 ├── UserCryptoProfile
 │       ├── RootKeyEnvelope
 │       └── RecoveryEnvelope
 │
 ├── Vault
 │    ├── VaultKeyEnvelope
 │    └── VaultItem
 │          └── ItemKeyEnvelope
 │
 ├── SyncEvent
 └── AuditEvent
```

---

# 4. Core Database Rules

## DB-001

No column named:

```text
password
secret
totpSecret
privateKey
cardNumber
```

may store vault plaintext.

---

## DB-002

Encrypted payload columns should use explicit names:

```text
ciphertext
encryptedPayload
keyEnvelope
```

---

## DB-003

Every encrypted object includes:

```text
protocolVersion
algorithmSuite
keyVersion
revision
```

where applicable.

---

## DB-004

All timestamps use:

```text
TIMESTAMPTZ
```

---

## DB-005

All user-controlled resources use opaque IDs.

Recommended:

```text
UUIDv7
```

or PostgreSQL UUIDs with equivalent semantics.

---

## DB-006

Authorization must never depend on identifier unpredictability.

---

# 5. User

Represents the account identity.

```text
users
```

Suggested fields:

```text
id                  UUID PRIMARY KEY
email               TEXT NOT NULL
normalized_email    TEXT NOT NULL
status              account_status NOT NULL
email_verified_at   TIMESTAMPTZ NULL

created_at          TIMESTAMPTZ NOT NULL
updated_at          TIMESTAMPTZ NOT NULL
deleted_at          TIMESTAMPTZ NULL
```

Classification:

| Field            | Classification    |
| ---------------- | ----------------- |
| id               | SERVER_METADATA   |
| email            | SECURITY_METADATA |
| normalized_email | SECURITY_METADATA |
| status           | SECURITY_METADATA |
| timestamps       | SERVER_METADATA   |

---

# 6. Account Status

Recommended enum:

```text
PENDING_VERIFICATION
ACTIVE
LOCKED
SUSPENDED
DELETION_PENDING
DELETED
```

Do not physically delete accounts immediately when user deletion starts.

Account deletion is a multi-stage security operation.

---

# 7. Email Constraints

Require unique normalized email:

```text
UNIQUE(normalized_email)
```

Normalize consistently before persistence.

Example:

```text
User@Example.com
```

becomes application-defined canonical form before uniqueness checks.

Do not rely on database collation behavior alone.

---

# 8. Authentication Identity

Authentication remains separate from vault encryption.

```text
authentication_identities
```

Suggested fields:

```text
id                  UUID PRIMARY KEY
user_id             UUID NOT NULL

type                auth_identity_type NOT NULL
provider             TEXT NULL
provider_subject     TEXT NULL

credential_data      BYTEA NULL
credential_version   INTEGER NOT NULL

created_at           TIMESTAMPTZ NOT NULL
updated_at           TIMESTAMPTZ NOT NULL
last_used_at         TIMESTAMPTZ NULL
```

Possible identity types:

```text
PASSWORD
PASSKEY
OIDC
SAML
```

V1 does not need to implement all of them.

---

# 9. Important Authentication Rule

`credential_data` belongs exclusively to authentication.

It must never contain:

```text
Master Password
Account Secret
ARK
vault-derived keys
```

The authentication system and vault unlocking system remain independent.

---

# 10. Password Authentication

If V1 includes password authentication, it must use dedicated authentication material.

Do not store:

```text
masterPasswordHash
```

as though the Master Password were a conventional backend credential.

The authentication protocol will receive its own specification before implementation.

Until then, the schema remains authentication-method agnostic.

---

# 11. User Crypto Profile

```text
user_crypto_profiles
```

One record per user.

Suggested fields:

```text
user_id                 UUID PRIMARY KEY

protocol_version        INTEGER NOT NULL
crypto_suite            TEXT NOT NULL

kdf_algorithm           TEXT NOT NULL
kdf_salt                BYTEA NOT NULL
kdf_memory_kib          INTEGER NOT NULL
kdf_iterations          INTEGER NOT NULL
kdf_parallelism         INTEGER NOT NULL

active_root_key_version INTEGER NOT NULL

created_at              TIMESTAMPTZ NOT NULL
updated_at              TIMESTAMPTZ NOT NULL
```

Classification:

```text
KDF salt       PUBLIC_CRYPTO
KDF params     SECURITY_METADATA / PUBLIC_CRYPTO
suite          PUBLIC_CRYPTO
versions       SERVER_METADATA
```

---

# 12. Account Secret

There is intentionally no:

```text
account_secret
```

column.

The server must not persist the Account Secret in plaintext.

---

# 13. Root Key Envelope

Wrapped ARK records:

```text
root_key_envelopes
```

Suggested fields:

```text
id                  UUID PRIMARY KEY
user_id             UUID NOT NULL

key_version         INTEGER NOT NULL
envelope_type       root_envelope_type NOT NULL

algorithm           TEXT NOT NULL
iv                   BYTEA NOT NULL
ciphertext          BYTEA NOT NULL

protocol_version    INTEGER NOT NULL

status              key_state NOT NULL

created_at          TIMESTAMPTZ NOT NULL
retired_at          TIMESTAMPTZ NULL
```

Envelope types:

```text
PASSWORD
RECOVERY
DEVICE
```

---

# 14. Root Envelope Constraints

Recommended uniqueness:

```text
UNIQUE(
    user_id,
    envelope_type,
    key_version
)
```

Multiple historical versions may exist during rotation.

Only one active password envelope should normally exist per active root version.

---

# 15. Recovery Envelope

Recovery can either reuse `root_key_envelopes` with:

```text
envelope_type = RECOVERY
```

or use an explicit table.

Preferred V1 design:

```text
recovery_envelopes
```

because recovery requires additional lifecycle metadata.

Fields:

```text
id                  UUID PRIMARY KEY
user_id             UUID NOT NULL

version             INTEGER NOT NULL
protocol_version    INTEGER NOT NULL

algorithm           TEXT NOT NULL
iv                  BYTEA NOT NULL
ciphertext          BYTEA NOT NULL

status              recovery_state NOT NULL

created_at          TIMESTAMPTZ NOT NULL
rotated_at          TIMESTAMPTZ NULL
used_at             TIMESTAMPTZ NULL
```

---

# 16. Recovery State

```text
ACTIVE
USED
ROTATED
REVOKED
```

A successful recovery should normally rotate recovery material.

---

# 17. Recovery Key

There is intentionally no:

```text
recovery_key
```

column.

Only the encrypted recovery ARK envelope exists server-side.

---

# 18. Vault

```text
vaults
```

V1 primarily has one personal vault.

Fields:

```text
id                  UUID PRIMARY KEY
owner_user_id       UUID NOT NULL

type                vault_type NOT NULL
status              vault_status NOT NULL

current_key_version INTEGER NOT NULL

created_at          TIMESTAMPTZ NOT NULL
updated_at          TIMESTAMPTZ NOT NULL
deleted_at          TIMESTAMPTZ NULL
```

Types:

```text
PERSONAL
ORGANIZATION
SHARED
```

Only:

```text
PERSONAL
```

is required for V1.

---

# 19. Vault Metadata

Do not store plaintext:

```text
vault_name
vault_description
```

unless explicitly required.

If custom vault names are introduced, they should normally be encrypted.

---

# 20. Vault Key Envelope

PVK wrapped by ARK.

```text
vault_key_envelopes
```

Fields:

```text
id                  UUID PRIMARY KEY
vault_id            UUID NOT NULL
owner_user_id       UUID NOT NULL

key_version         INTEGER NOT NULL
root_key_version    INTEGER NOT NULL

algorithm           TEXT NOT NULL
iv                  BYTEA NOT NULL
ciphertext          BYTEA NOT NULL

protocol_version    INTEGER NOT NULL
status              key_state NOT NULL

created_at          TIMESTAMPTZ NOT NULL
retired_at          TIMESTAMPTZ NULL
```

---

# 21. Vault Key Constraint

```text
UNIQUE(vault_id, key_version)
```

This enables historical interpretation during rotations.

---

# 22. Vault Item

```text
vault_items
```

The backend treats each item as opaque encrypted data.

Fields:

```text
id                  UUID PRIMARY KEY
vault_id            UUID NOT NULL

revision            BIGINT NOT NULL
protocol_version    INTEGER NOT NULL

encrypted_payload   BYTEA NOT NULL

payload_algorithm   TEXT NOT NULL
payload_iv          BYTEA NOT NULL

item_key_version    INTEGER NOT NULL

created_at          TIMESTAMPTZ NOT NULL
updated_at          TIMESTAMPTZ NOT NULL
deleted_at          TIMESTAMPTZ NULL
```

---

# 23. What VaultItem Does Not Contain

No columns such as:

```text
name
username
url
password
notes
type
totp
favorite
folder
```

All of these remain inside:

```text
encrypted_payload
```

---

# 24. Item Payload

Client plaintext may conceptually contain:

```json
{
  "type": "login",
  "name": "GitHub",
  "username": "user@example.com",
  "password": "...",
  "urls": ["https://github.com"],
  "notes": "...",
  "customFields": []
}
```

Database receives only:

```text
ciphertext
```

---

# 25. Item Key Envelope

Each item revision has a wrapped IK.

```text
item_key_envelopes
```

Fields:

```text
id                  UUID PRIMARY KEY
item_id             UUID NOT NULL
item_revision       BIGINT NOT NULL

container_key_id    UUID NOT NULL
container_key_version INTEGER NOT NULL

algorithm           TEXT NOT NULL
iv                  BYTEA NOT NULL
ciphertext          BYTEA NOT NULL

protocol_version    INTEGER NOT NULL

created_at          TIMESTAMPTZ NOT NULL
```

---

# 26. Item Key Constraint

```text
UNIQUE(item_id, item_revision)
```

Every revision has one canonical IK envelope in V1.

Sharing may later allow multiple envelopes.

---

# 27. Why Separate ItemKeyEnvelope

Do not embed everything into one giant `vault_items` blob.

Separating:

```text
payload ciphertext
```

from:

```text
key envelope
```

allows:

- PVK rotation
- future collection sharing
- rewrapping without payload encryption
- crypto migrations
- cleaner auditing

---

# 28. Item Revision History

Two possible models exist:

### Model A

Overwrite current item and maintain separate history.

### Model B

Every revision is immutable.

For a serious password manager, prefer:

```text
immutable item revisions
```

---

# 29. Recommended Revision Model

Use:

```text
vault_items
```

for logical identity.

And:

```text
vault_item_revisions
```

for immutable encrypted revisions.

---

# 30. VaultItem Revised Model

```text
vault_items
```

Fields:

```text
id                  UUID PRIMARY KEY
vault_id            UUID NOT NULL

current_revision    BIGINT NOT NULL
status              item_status NOT NULL

created_at          TIMESTAMPTZ NOT NULL
updated_at          TIMESTAMPTZ NOT NULL
deleted_at          TIMESTAMPTZ NULL
```

No encrypted payload here.

---

# 31. VaultItemRevision

```text
vault_item_revisions
```

Fields:

```text
id                  UUID PRIMARY KEY
item_id             UUID NOT NULL

revision            BIGINT NOT NULL
protocol_version    INTEGER NOT NULL

payload_algorithm   TEXT NOT NULL
payload_iv          BYTEA NOT NULL
encrypted_payload   BYTEA NOT NULL

created_by_device_id UUID NULL

created_at          TIMESTAMPTZ NOT NULL
```

Constraint:

```text
UNIQUE(item_id, revision)
```

This is the preferred V1 design.

---

# 32. Current Revision

`vault_items.current_revision` points logically to:

```text
vault_item_revisions.revision
```

for that item.

Updating an item:

```text
INSERT new revision

UPDATE vault_items.current_revision

INSERT sync event

INSERT audit event
```

inside one transaction.

---

# 33. Item Status

Recommended:

```text
ACTIVE
DELETED
```

Potential future:

```text
ARCHIVED
```

Do not overload deletion and archival semantics.

---

# 34. Tombstones

Deleted items must remain discoverable by syncing clients.

Deletion therefore creates:

```text
DELETED state
+
sync event
```

Actual data cleanup happens later according to retention policy.

---

# 35. Sessions

Prefer server-managed opaque sessions.

```text
sessions
```

Fields:

```text
id                  UUID PRIMARY KEY
user_id             UUID NOT NULL
device_id           UUID NULL

token_hash          BYTEA NOT NULL

status              session_status NOT NULL

created_at          TIMESTAMPTZ NOT NULL
last_seen_at        TIMESTAMPTZ NULL
expires_at          TIMESTAMPTZ NOT NULL
revoked_at          TIMESTAMPTZ NULL

ip_created          INET NULL
user_agent_hash     BYTEA NULL
```

---

# 36. Session Tokens

Never store plaintext session tokens.

Store:

```text
SHA-256(randomSessionToken)
```

or equivalent secure token lookup representation.

Client holds:

```text
randomSessionToken
```

Database holds:

```text
tokenHash
```

A session-database leak should not immediately provide usable bearer tokens.

---

# 37. Session Status

```text
ACTIVE
REVOKED
EXPIRED
```

---

# 38. Session Indexes

Critical:

```text
INDEX(token_hash)
INDEX(user_id, status)
INDEX(expires_at)
```

---

# 39. Device

```text
devices
```

Fields:

```text
id                  UUID PRIMARY KEY
user_id             UUID NOT NULL

name_ciphertext     BYTEA NULL
platform            TEXT NULL
client_type         device_client_type NOT NULL

status              device_status NOT NULL

first_seen_at       TIMESTAMPTZ NOT NULL
last_seen_at        TIMESTAMPTZ NULL
revoked_at          TIMESTAMPTZ NULL
```

Possible:

```text
WEB
DESKTOP
IOS
ANDROID
BROWSER_EXTENSION
```

---

# 40. Device Name

Device names can leak information.

Example:

```text
Daniel MacBook Production
```

Therefore custom device labels should preferably be encrypted.

Generic platform metadata may remain server-readable.

---

# 41. Device Key Envelope

Future trusted devices:

```text
device_key_envelopes
```

Fields:

```text
id                  UUID PRIMARY KEY
device_id           UUID NOT NULL
user_id             UUID NOT NULL

root_key_version    INTEGER NOT NULL

algorithm           TEXT NOT NULL
iv                  BYTEA NOT NULL
ciphertext          BYTEA NOT NULL

created_at          TIMESTAMPTZ NOT NULL
revoked_at          TIMESTAMPTZ NULL
```

Not required for the first web-only implementation.

---

# 42. Sync State

Each user receives monotonically increasing sync sequence numbers.

Possible table:

```text
account_sync_state
```

Fields:

```text
user_id             UUID PRIMARY KEY
current_sequence    BIGINT NOT NULL
updated_at          TIMESTAMPTZ NOT NULL
```

---

# 43. Sync Event

```text
sync_events
```

Fields:

```text
sequence            BIGINT NOT NULL
user_id             UUID NOT NULL

entity_type         sync_entity_type NOT NULL
entity_id           UUID NOT NULL
operation           sync_operation NOT NULL

entity_revision     BIGINT NULL

created_at          TIMESTAMPTZ NOT NULL
```

Primary key may be:

```text
(user_id, sequence)
```

---

# 44. Sync Operations

```text
UPSERT
DELETE
KEY_ROTATION
SECURITY_STATE_CHANGE
```

Keep the event vocabulary small.

---

# 45. Sync Payload Strategy

Do not necessarily duplicate ciphertext inside `sync_events`.

Preferred:

```text
sync event
   ↓
references entity
   ↓
sync API loads current encrypted representation
```

Advantages:

- less duplicate encrypted data
- smaller database
- cleaner retention

For immutable historical sync semantics, this can be revisited later.

---

# 46. Sync Sequence Allocation

Sequence increment and mutation must happen transactionally.

Conceptually:

```text
BEGIN

UPDATE account_sync_state
SET current_sequence = current_sequence + 1
RETURNING current_sequence

INSERT vault_item_revision

UPDATE vault_item

INSERT sync_event

INSERT audit_event

COMMIT
```

---

# 47. Concurrency

Client sends:

```text
expectedRevision
```

Update condition:

```text
current_revision = expectedRevision
```

If zero rows update:

```text
409 CONFLICT
```

Do not silently overwrite secrets.

---

# 48. Audit Event

```text
audit_events
```

Fields:

```text
id                  UUID PRIMARY KEY

user_id             UUID NULL
actor_user_id       UUID NULL
session_id          UUID NULL
device_id           UUID NULL

event_type          TEXT NOT NULL

target_type         TEXT NULL
target_id           UUID NULL

request_id          UUID NULL

ip_address          INET NULL

metadata            JSONB NULL

created_at          TIMESTAMPTZ NOT NULL
```

---

# 49. Audit Metadata Policy

`metadata` must have an allowlist.

Never arbitrarily serialize application objects into audit events.

Safe:

```json
{
  "previousKeyVersion": 3,
  "newKeyVersion": 4
}
```

Unsafe:

```json
{
  "requestBody": "..."
}
```

---

# 50. Audit Immutability

Application role should ideally have:

```text
INSERT
SELECT
```

but not routine:

```text
UPDATE
DELETE
```

on audit records.

Later versions may use:

- append-only storage
- signed audit chains
- external SIEM export

---

# 51. Request Idempotency

Sensitive POST operations should support idempotency.

```text
idempotency_keys
```

Fields:

```text
user_id             UUID NOT NULL
idempotency_key     TEXT NOT NULL

request_hash        BYTEA NOT NULL
response_code       INTEGER NULL

created_at          TIMESTAMPTZ NOT NULL
expires_at          TIMESTAMPTZ NOT NULL
```

Useful for:

```text
account creation
item creation
device enrollment
recovery
```

---

# 52. Rate Limit State

Do not store durable rate-limit counters in PostgreSQL unless necessary.

Use Redis for:

```text
login attempts
recovery attempts
registration attempts
```

PostgreSQL remains authoritative only for durable security state.

---

# 53. Key State Enum

Reusable:

```text
ACTIVE
ROTATING
RETIRED
COMPROMISED
DESTROYED
```

---

# 54. Foreign Key Strategy

Examples:

```text
user_crypto_profiles.user_id
    → users.id

vaults.owner_user_id
    → users.id

vault_key_envelopes.vault_id
    → vaults.id

vault_items.vault_id
    → vaults.id

vault_item_revisions.item_id
    → vault_items.id

sessions.user_id
    → users.id
```

Use real foreign keys.

Security-sensitive relational integrity should not depend entirely on application logic.

---

# 55. Delete Strategy

Do not casually use:

```text
ON DELETE CASCADE
```

on security-critical records.

Deleting a user should be an explicit workflow.

Examples requiring careful treatment:

```text
sessions
audit events
encrypted vaults
recovery state
attachments
backups
```

---

# 56. Account Deletion Workflow

Conceptually:

```text
User requests deletion
        ↓
DELETION_PENDING
        ↓
Revoke sessions
        ↓
Revoke devices
        ↓
Retention delay
        ↓
Destroy active key envelopes
        ↓
Delete ciphertext
        ↓
Schedule attachment deletion
        ↓
Process backup retention
        ↓
DELETED
```

---

# 57. Crypto-Shredding

One strong deletion step is destruction of:

```text
Root key envelopes
Vault key envelopes
Item key envelopes
```

Even if encrypted blobs temporarily remain in backups, removing recoverable key envelopes can make them cryptographically inaccessible.

Backup lifecycle must still be respected.

---

# 58. Indexing Strategy

Important indexes:

```text
users(normalized_email)

authentication_identities(user_id)

sessions(token_hash)
sessions(user_id, status)

devices(user_id, status)

vaults(owner_user_id, status)

vault_items(vault_id, status)

vault_item_revisions(item_id, revision DESC)

sync_events(user_id, sequence)

audit_events(user_id, created_at DESC)
audit_events(event_type, created_at DESC)
```

---

# 59. Ciphertext Indexing

Do not attempt:

```text
INDEX(encrypted_payload)
```

for semantic search.

Searching encrypted credentials is a client-side concern in V1.

---

# 60. Vault Search

Flow:

```text
Sync encrypted vault locally
        ↓
Decrypt locally
        ↓
Build in-memory/local search index
        ↓
Search locally
```

The server should not receive queries such as:

```text
"bank"
"github"
"AWS"
```

because search terms themselves reveal sensitive metadata.

---

# 61. Sizes

All binary crypto fields must enforce reasonable maximum sizes.

Example:

```text
root key envelope
    small

item ciphertext
    bounded

attachment
    object storage
```

Do not permit arbitrary multi-gigabyte values in database item columns.

---

# 62. Payload Size Limits

Initial example limits:

```text
Vault Item Encrypted Payload
    1 MiB maximum

Key Envelope
    16 KiB maximum

Audit Metadata
    16 KiB maximum
```

Exact limits can be adjusted later.

Limits protect against resource exhaustion.

---

# 63. Attachments

Do not store large encrypted attachments directly in PostgreSQL.

Future table:

```text
attachments
```

Fields:

```text
id                  UUID PRIMARY KEY
item_id             UUID NOT NULL

object_key          TEXT NOT NULL

size_bytes          BIGINT NOT NULL
encrypted_metadata  BYTEA NULL

status              attachment_status NOT NULL

created_at          TIMESTAMPTZ NOT NULL
deleted_at          TIMESTAMPTZ NULL
```

Actual blob:

```text
S3-compatible object storage
```

---

# 64. Attachment Key Envelope

Future:

```text
attachment_key_envelopes
```

with:

```text
attachment_id
item_revision
algorithm
iv
ciphertext
protocol_version
```

---

# 65. Future Organizations

Do not implement yet, but reserve architecture for:

```text
organizations
organization_members
groups
group_members
collections
collection_members
collection_key_envelopes
```

Personal vaults and organization collections should eventually use compatible envelope semantics.

---

# 66. Multi-Tenant Security

Every tenant-owned query must include authorization scope.

Wrong:

```sql
SELECT *
FROM vault_items
WHERE id = $1;
```

Correct conceptual approach:

```sql
SELECT vi.*
FROM vault_items vi
JOIN vaults v ON v.id = vi.vault_id
WHERE vi.id = $1
  AND v.owner_user_id = $authenticatedUser;
```

The service layer must enforce ownership regardless of ID knowledge.

---

# 67. Row-Level Security

PostgreSQL Row-Level Security may later provide defense in depth.

Do not initially depend on RLS as the sole authorization mechanism.

Primary authorization remains application-controlled.

RLS can become a second barrier.

---

# 68. Database Roles

At minimum:

```text
db_owner
db_migrator
db_application
db_backup
db_readonly_security
```

The running API uses:

```text
db_application
```

It should not own the schema.

---

# 69. Application DB Permissions

Application role generally needs:

```text
SELECT
INSERT
UPDATE
```

and controlled:

```text
DELETE
```

on application tables.

It does not need:

```text
CREATE TABLE
ALTER TABLE
DROP TABLE
CREATE ROLE
```

---

# 70. Migration Role

Only migration tooling receives:

```text
CREATE
ALTER
DROP
```

schema permissions.

Migration credentials must not be available to runtime containers.

---

# 71. Backup Role

Backup access should be independent from application runtime access.

Backup operators do not need application credentials.

---

# 72. Prisma Considerations

If Prisma is selected:

```text
Prisma
   ↓
application queries
```

but raw SQL migrations may still be necessary for:

- CHECK constraints
- specialized indexes
- RLS
- database roles
- advanced PostgreSQL features

ORM convenience must not prevent database-level security constraints.

---

# 73. Recommended V1 Prisma-Level Models

Conceptually:

```text
User
AuthenticationIdentity
UserCryptoProfile

RootKeyEnvelope
RecoveryEnvelope

Session
Device

Vault
VaultKeyEnvelope

VaultItem
VaultItemRevision
ItemKeyEnvelope

AccountSyncState
SyncEvent

AuditEvent
```

---

# 74. Transaction: Create Item

One transaction:

```text
BEGIN

verify vault ownership

INSERT vault_item

INSERT vault_item_revision

INSERT item_key_envelope

increment sync sequence

INSERT sync_event

INSERT audit_event

COMMIT
```

If any step fails:

```text
ROLLBACK
```

---

# 75. Transaction: Update Item

```text
BEGIN

verify authorization

compare expectedRevision

INSERT new immutable revision

INSERT new IK envelope

UPDATE current_revision

increment sync sequence

INSERT sync event

INSERT audit event

COMMIT
```

---

# 76. Transaction: Delete Item

```text
BEGIN

verify authorization

mark item DELETED

increment revision

create sync tombstone

insert audit event

COMMIT
```

Physical cleanup occurs asynchronously later.

---

# 77. Transaction: Master Password Change

Database sees only:

```text
new KDF parameters
new password ARK envelope
```

Transaction:

```text
BEGIN

insert new root envelope

update active root/password envelope metadata

retire previous password envelope

insert audit event

increment security revision

COMMIT
```

No item re-encryption occurs.

---

# 78. Transaction: Recovery

```text
BEGIN

validate recovery authorization state

replace password ARK envelope

rotate recovery envelope

revoke old sessions

optionally revoke devices

write audit events

update security revision

COMMIT
```

Recovery must have strict replay protection.

---

# 79. Security Revision

Besides sync revision, accounts should eventually maintain:

```text
security_revision
```

Increment when:

```text
password changed
recovery completed
session reset
device revoked
root key rotated
```

Clients can react to significant security changes independently from ordinary vault sync.

---

# 80. Database Restore Protection

Old database backups may contain outdated:

```text
sessions
devices
recovery state
key states
```

A restore procedure must not automatically make old security state authoritative.

We should eventually maintain critical revocation data through:

```text
independent security ledger
or
restore reconciliation process
```

This is not required for local development but is required before serious production deployment.

---

# 81. Audit Retention

Audit records should outlive normal operational records.

Example future policy:

```text
User operational data:
    account lifetime

Security audit:
    defined retention period

Enterprise audit:
    customer-configurable / compliance-driven
```

Exact retention must be defined before production.

---

# 82. Database Encryption

Database storage encryption remains mandatory.

But:

```text
PostgreSQL encryption at rest
```

is defense in depth.

It does not replace:

```text
client-side vault encryption
```

---

# 83. Database Logs

PostgreSQL logging must not include complete parameter payloads for vault APIs.

Avoid configurations that could log:

```text
ciphertexts
session tokens
authentication credentials
```

Ciphertexts are not plaintext secrets, but unnecessarily duplicating them into logs still increases exposure and retention complexity.

---

# 84. Schema Invariants

### DBINV-001

No vault plaintext exists in any database table.

### DBINV-002

No Master Password exists in any database table.

### DBINV-003

No Account Secret exists in plaintext server-side.

### DBINV-004

No Recovery Key exists server-side.

### DBINV-005

No ARK/PVK/IK exists unwrapped.

### DBINV-006

Every encrypted object is versioned.

### DBINV-007

Item revisions are immutable.

### DBINV-008

All mutations generate synchronization state.

### DBINV-009

Security-sensitive mutations generate audit events.

### DBINV-010

Sessions are immediately revocable.

### DBINV-011

Plaintext session tokens are not stored.

### DBINV-012

Searchable vault fields remain encrypted.

---

# 85. Recommended V1 Schema

Final V1 tables:

```text
users

authentication_identities
user_crypto_profiles

root_key_envelopes
recovery_envelopes

sessions
devices

vaults
vault_key_envelopes

vault_items
vault_item_revisions
item_key_envelopes

account_sync_state
sync_events

audit_events
```

Optional early table:

```text
idempotency_keys
```

---

# 86. First Vertical Slice

The first implementation does not require every table.

Minimum slice:

```text
users
authentication_identities
user_crypto_profiles

root_key_envelopes
recovery_envelopes

sessions

vaults
vault_key_envelopes

vault_items
vault_item_revisions
item_key_envelopes
```

This is enough to prove:

```text
register
authenticate
unlock
create encrypted item
reload
decrypt
```

---

# 87. What Comes Next

Before writing the Prisma schema, define:

```text
07_AUTHENTICATION_AND_SESSION_PROTOCOL.md
```

because:

```text
authentication identity
session issuance
cookies
passkeys
password login
CSRF
reauthentication
```

still need an exact protocol.

After that:

```text
08_API_CONTRACT.md
09_PRISMA_SCHEMA.md
10_PROJECT_BOOTSTRAP.md
```

and implementation can begin.

---

# 88. Architecture Milestone

At this point the project has defined:

```text
Product Security Baseline
Threat Model
Cryptographic Architecture
Key Lifecycle
System Architecture
Database Architecture
```

The remaining major blocker before code is:

> How does a user authenticate to the server without coupling server authentication to vault decryption?

That is the purpose of the next document.
