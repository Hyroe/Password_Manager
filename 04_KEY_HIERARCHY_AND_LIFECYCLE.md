# Enterprise Password Manager

## Key Hierarchy and Lifecycle

**Status:** Draft v0.1
**Protocol Version:** 1
**Depends On:** `03_CRYPTOGRAPHIC_ARCHITECTURE.md`

---

# 1. Objective

Define the complete lifecycle of every cryptographic secret used by the platform.

For every key we must know:

```text
Who creates it?
Where does it exist?
Where is it stored?
What protects it?
What does it protect?
When is it loaded?
When is it rotated?
When is it revoked?
How is compromise handled?
When is it destroyed?
```

No cryptographic key may exist without an explicit lifecycle.

---

# 2. Final V1 Key Hierarchy

V1 will use:

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
    HKDF
      │
      ▼
    MKEK
      │
      ▼
     ARK
      │
      ├── Personal Vault Key
      │       │
      │       └── Item Keys
      │               │
      │               └── Attachment Keys
      │
      ├── User Private Sharing Key
      │
      └── Future Vault Keys
```

Recovery provides an independent path:

```text
Recovery Key
      │
      ▼
Recovery KEK
      │
      ▼
     ARK
```

Trusted native devices may later provide:

```text
Device Root Key
      │
      ▼
     ARK
```

---

# 3. Decision: Account Secret

V1 WILL include an **Account Secret**.

This is now part of the baseline architecture.

The Account Secret is:

```text
Random
High entropy
Generated client-side
Unique per account
Not stored by the backend in plaintext
```

Conceptually:

```text
Master Password
       +
Account Secret
       +
KDF Salt
       ↓
    Argon2id
       ↓
      MPK
```

---

# 4. Why Account Secret Exists

Without an Account Secret:

```text
Database Leak
      ↓
Wrapped ARK
KDF Salt
KDF Parameters
      ↓
Offline password guessing
```

With an Account Secret:

```text
Database Leak
      ↓
Missing Account Secret
      ↓
Master-password-only attack is insufficient
```

The Account Secret therefore provides an additional high-entropy factor against server/database compromise.

It is not intended to replace:

- Strong passwords
- MFA
- Passkeys
- Argon2id

It specifically strengthens the vault-encryption path.

---

# 5. Account Secret Storage

The Account Secret may exist in:

```text
Trusted client
Recovery Kit
Secure local storage
Explicitly approved enrollment flow
```

It must not exist in plaintext in:

```text
Backend database
Logs
Analytics
Email
Support tools
SIEM
Application telemetry
```

---

# 6. Account Secret Format

Internally:

```text
256 random bits
```

For user-facing representation:

```text
versioned + encoded + checksummed
```

Example conceptually:

```text
AS1-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
```

This is only a presentation format.

The exact encoding will be defined separately.

---

# 7. Account Secret Lifecycle

## Creation

Generated client-side during account creation.

```text
CSPRNG
   ↓
Account Secret
```

## Storage

Immediately included in the Recovery Kit.

May also be stored inside trusted secure client storage.

## Server

Never sent as plaintext.

## Rotation

Rare.

Rotation requires:

```text
Current ARK access
        ↓
Generate new Account Secret
        ↓
derive new MKEK
        ↓
re-wrap ARK
```

## Compromise

If Account Secret leaks but Master Password remains unknown:

- Vault should remain protected.

If both leak:

- Re-wrap ARK using new credentials.
- Invalidate affected trusted devices where appropriate.

---

# 8. Master Password

## Created By

User.

## Stored By

Nobody.

The backend must never store the Master Password.

## Used For

Together with Account Secret and KDF parameters:

```text
Master Password
+
Account Secret
+
Salt
   ↓
Argon2id
   ↓
MPK
```

## Lifetime

Only while deriving unlocking material.

## Memory

Should be released as soon as practical after key derivation.

## Rotation

User may change it at any time.

Changing the Master Password does not rotate ARK automatically.

---

# 9. Master Password Key — MPK

## Created By

Crypto Core.

## Input

```text
Master Password
Account Secret
KDF Salt
KDF Parameters
```

## Output

```text
256-bit MPK
```

## Storage

Never persisted.

## Lifetime

Ephemeral.

## Purpose

Input to subkey derivation.

Application code must not use MPK directly.

## Destruction

Discard as soon as required subkeys have been derived.

---

# 10. Master Key Encryption Key — MKEK

## Created By

Derived from MPK using HKDF.

Example domain:

```text
credential-manager/mkek/v1
```

## Purpose

Wrap and unwrap ARK.

Nothing else.

## Storage

Never server-side.

Normally never persist directly.

## Lifetime

Unlock operation.

Native trusted-device workflows may avoid deriving MKEK on every unlock.

---

# 11. Account Root Key — ARK

## Created By

Client Crypto Core.

## Generation

```text
CSPRNG → 256-bit random key
```

## Purpose

Highest user-controlled root key.

ARK protects:

```text
PVK
USK
future user-level keys
```

ARK does not directly encrypt vault items.

---

# 12. ARK Storage

Server stores only encrypted envelopes.

Potential envelopes:

```text
Password Envelope
Recovery Envelope
Device Envelope
```

Conceptually:

```text
ARK
 ├── wrapped by MKEK
 ├── wrapped by Recovery KEK
 └── wrapped by Device Key
```

No plaintext ARK exists server-side.

---

# 13. ARK Lifetime

While vault is unlocked:

```text
ARK may exist in protected client memory
```

When vault locks:

```text
ARK reference is removed
dependent decrypted keys are removed
plaintext item cache is cleared
```

---

# 14. ARK Rotation

ARK rotation is exceptional.

It is required after suspected:

```text
ARK compromise
Recovery mechanism compromise
major crypto migration
```

ARK rotation is significantly more expensive than a Master Password change.

Flow:

```text
Old ARK
   ↓
unwrap subordinate keys
   ↓
New ARK
   ↓
rewrap subordinate keys
```

Item payloads do not necessarily need re-encryption.

---

# 15. ARK Compromise

ARK compromise is a critical security incident.

Required actions:

```text
Generate new ARK
Rotate all user-controlled subordinate keys where necessary
Invalidate recovery envelopes
Invalidate device envelopes
Rotate sharing keys if affected
Review sessions
Revoke devices if needed
Generate new Recovery Kit
```

Historical ciphertext protected by compromised keys should be considered potentially exposed.

---

# 16. Personal Vault Key — PVK

## Created By

Client.

## Generation

```text
CSPRNG → 256 bits
```

## Protected By

ARK.

## Purpose

Wrap Item Keys belonging to the personal vault.

PVK does not normally encrypt item payloads directly.

---

# 17. PVK Rotation

Rotate when:

```text
Vault-level compromise suspected
Major cryptographic migration
Explicit security operation
```

Rotation:

```text
PVK v1
   ↓
unwrap IK envelopes
   ↓
PVK v2
   ↓
rewrap IK envelopes
```

Item ciphertext remains unchanged.

---

# 18. Item Key — IK

Each item revision receives an independent key.

## Created By

Client.

## Generation

```text
CSPRNG → 256 bits
```

## Purpose

Encrypt one item revision.

Example:

```text
IK
 ↓
AES-256-GCM
 ↓
Encrypted Item
```

## Protected By

PVK or Collection Key.

---

# 19. Item Key Lifetime

Generated during:

```text
item creation
item update
item secret rotation
```

Loaded only when decrypting the corresponding item.

Avoid keeping all IKs decrypted permanently.

---

# 20. Item Revision Policy

Every modification creates:

```text
new item revision
+
new IK
+
new IV
```

Example:

```text
revision 12 → IK12
revision 13 → IK13
```

This creates clean cryptographic isolation between revisions.

---

# 21. Item Deletion

Deleting an item produces:

```text
tombstone
```

rather than immediate physical deletion.

This allows synchronization.

After the retention period:

```text
ciphertext removed
key envelope removed
attachment envelopes removed
```

Deletion policies must consider backups separately.

---

# 22. Crypto-Shredding

Destroying a key can make corresponding ciphertext inaccessible.

Example:

```text
Destroy IK
     ↓
Encrypted Item becomes cryptographically unreadable
```

This technique may support secure deletion semantics.

However:

> Crypto-shredding cannot erase copies of plaintext previously exported or decrypted.

---

# 23. Attachment Key — AK

Every attachment receives an independent random key.

```text
CSPRNG
 ↓
AK
```

AK encrypts attachment data.

AK is wrapped by the corresponding item/container encryption hierarchy.

---

# 24. Attachment Lifecycle

Creation:

```text
Generate AK
Encrypt attachment
Wrap AK
Upload ciphertext
```

Reading:

```text
Download ciphertext
Unwrap AK
Decrypt locally
```

Deletion:

```text
Delete encrypted blob
Delete AK envelope
```

Large attachment chunk encryption will receive a dedicated protocol.

---

# 25. Personal Recovery Key — PRK

## Created By

Client during onboarding.

## Generation

```text
CSPRNG
```

## Purpose

Provide an independent cryptographic recovery path to ARK.

## Backend

Never receives plaintext PRK.

---

# 26. Recovery Key Material

PRK derives:

```text
Recovery KEK
```

using explicit domain separation.

Example:

```text
credential-manager/recovery-kek/v1
```

Recovery KEK wraps ARK.

---

# 27. Recovery Kit

The Recovery Kit should eventually contain:

```text
User Identifier
Account Secret
Recovery Key
Protocol Version
Recovery Instructions
Verification checksum
```

It must not contain:

```text
Master Password
Plaintext Vault Key
Plaintext Vault Contents
```

---

# 28. Recovery Kit Generation

Generated entirely client-side.

Potential formats:

```text
Printable PDF
Offline text representation
QR representation
```

This artifact is extremely sensitive.

The user must explicitly acknowledge its importance.

---

# 29. Recovery Key Rotation

Required after:

```text
Recovery Kit lost
Recovery Kit viewed by unauthorized person
Recovery Key suspected compromise
Successful recovery operation
```

Flow:

```text
Current ARK
   ↓
New PRK
   ↓
New Recovery KEK
   ↓
New Recovery ARK Envelope
```

Old recovery envelope becomes invalid.

---

# 30. User Sharing Key Pair

Future sharing requires:

```text
UPK
USK
```

## UPK

Public.

May be stored plaintext server-side.

## USK

Private.

Must remain encrypted.

---

# 31. USK Protection

USK is protected by ARK-controlled material.

Conceptually:

```text
ARK
 ↓
User Private Key Protection
 ↓
Encrypted USK
```

Exact key derivation/wrapping mechanics will be frozen in the sharing protocol.

---

# 32. User Key Pair Rotation

Rotation may be necessary after:

```text
USK compromise
cryptographic migration
user security reset
```

Public-key rotation requires careful handling of existing shared envelopes.

Therefore user-key versions are mandatory.

Example:

```text
userKeyVersion = 4
```

---

# 33. Collection Key — CK

Shared resources use independent Collection Keys.

## Created By

Authorized client.

## Generation

```text
CSPRNG → 256 bits
```

## Purpose

Wrap IKs belonging to the shared collection.

---

# 34. CK Distribution

CK itself is encrypted independently for each authorized member.

```text
CK
 ├── envelope → Alice
 ├── envelope → Bob
 └── envelope → Charlie
```

The server stores these envelopes.

The server cannot recover CK.

---

# 35. CK Membership Change

## Member Added

Create a new CK envelope for the member.

No key rotation necessarily required.

## Member Removed

Rotate CK.

```text
CK v7
 ↓
CK v8
```

Remaining IKs are rewrapped to CK v8.

Removed member receives no CK v8 envelope.

---

# 36. CK Compromise

If CK leaks:

```text
Generate CK replacement
Rewrap affected IKs
Reissue member envelopes
Consider rotating underlying external credentials
```

Past ciphertext accessible with the compromised CK may remain compromised.

---

# 37. Device Root Key — DRK

Native clients may generate:

```text
DRK
```

inside OS-protected storage.

Examples:

```text
Secure Enclave
Android Keystore
TPM-backed key
OS Keychain
```

---

# 38. DRK Purpose

DRK supports:

```text
trusted-device unlock
biometric unlock
device-bound ARK envelope
```

Instead of asking for Master Password on every unlock.

---

# 39. DRK Storage

Preferred:

```text
Non-exportable hardware/OS protected key
```

If the platform cannot support this safely, trusted-device unlock should not be enabled.

---

# 40. Device Enrollment

A new device must not automatically receive ARK simply because it has an authenticated session.

Enrollment requires additional authorization.

Potential mechanisms:

```text
Master Password + Account Secret
Existing trusted device approval
Recovery Kit
Enterprise-managed enrollment
```

---

# 41. Device Enrollment Flow

Example:

```text
New Device
   ↓
Account Authentication
   ↓
Device registration
   ↓
User proves vault-unlock capability
   ↓
Generate DRK
   ↓
Create ARK device envelope
   ↓
Trusted Device
```

---

# 42. Device Revocation

Revocation removes:

```text
Device authorization
Session authorization
Device ARK envelope
```

Future sync is denied.

Important limitation:

> Revocation cannot erase secrets that were previously decrypted on the device.

---

# 43. Device Signing Key — DSK

Future versions may give each device a signing key.

Possible uses:

```text
signed sync operations
device approval
anti-replay
device provenance
```

DSK is independent from DRK.

Never reuse an encryption key as a signing key.

---

# 44. Organization Keys

Enterprise organizations will require a separate hierarchy.

Conceptually:

```text
Organization
     │
     ├── Collection Keys
     ├── Recovery Authority Keys
     └── Membership Key Envelopes
```

No global platform organization master key is permitted.

---

# 45. Organization Recovery Key — ORK

Optional.

Created when enterprise recovery policy is enabled.

The vendor must not possess the private recovery key.

Potential ownership:

```text
organization security authority
HSM-backed enterprise key
threshold recovery authorities
```

Detailed design belongs in the enterprise recovery protocol.

---

# 46. Key Storage Matrix

| Key             | Server plaintext |         Client memory |       Client persistent |        Recovery Kit |
| --------------- | ---------------: | --------------------: | ----------------------: | ------------------: |
| Master Password |            Never |             Temporary |                   Never |               Never |
| Account Secret  |            Never |                   Yes |         Trusted storage |                 Yes |
| MPK             |            Never |             Temporary |                   Never |                  No |
| MKEK            |            Never |             Temporary |              Usually no |                  No |
| ARK             |            Never |        While unlocked |            Only wrapped |   Indirect recovery |
| PVK             |            Never |             As needed |            Only wrapped |                  No |
| IK              |            Never |             As needed |            Only wrapped |                  No |
| AK              |            Never |             As needed |            Only wrapped |                  No |
| PRK             |            Never |       During recovery | Optional secure storage |                 Yes |
| USK             |            Never |             As needed |          Encrypted only |                  No |
| UPK             |              Yes |                   Yes |                     Yes |                  No |
| DRK             |            Never |         OS controlled |   Secure hardware/store |                  No |
| CK              |            Never |             As needed |            Wrapped only |                  No |
| ORK private     |            Never | Enterprise controlled |      HSM/secure storage | Enterprise-specific |

---

# 47. Rotation Matrix

| Event                                | Keys Rotated                  |
| ------------------------------------ | ----------------------------- |
| Master Password changed              | MKEK / ARK envelope           |
| Account Secret changed               | MPK/MKEK path + ARK envelope  |
| Recovery Kit compromised             | PRK + recovery envelope       |
| Personal vault compromise            | PVK                           |
| Item edited                          | IK                            |
| Attachment replaced                  | AK                            |
| Member removed                       | CK                            |
| User private sharing key compromised | USK/UPK                       |
| Trusted device compromised           | DRK envelope revoked          |
| ARK compromised                      | ARK + dependent hierarchy     |
| Crypto-suite migration               | Depends on affected primitive |

---

# 48. Compromise Severity

## Tier 1 — Local Leaf Key

Examples:

```text
IK
AK
```

Blast radius:

```text
single item
single attachment
```

---

## Tier 2 — Container Key

Examples:

```text
PVK
CK
```

Blast radius:

```text
vault
collection
```

---

## Tier 3 — User Root Key

```text
ARK
```

Blast radius:

```text
entire user cryptographic hierarchy
```

Critical incident.

---

## Tier 4 — Recovery / Identity Root

Examples:

```text
PRK + identity compromise
Account Secret + Master Password
```

May result in total account compromise.

Critical incident.

---

# 49. Key IDs

Every persistent key envelope should reference:

```text
keyId
keyVersion
```

Example:

```json
{
  "keyId": "ck_fae193...",
  "keyVersion": 8
}
```

Keys must never be identified only by:

```text
"current"
```

because historical encrypted objects must remain interpretable.

---

# 50. Key State

Persistent key metadata may have states:

```text
ACTIVE
ROTATING
RETIRED
COMPROMISED
DESTROYED
```

Not all states imply that plaintext key material exists server-side.

They represent lifecycle metadata.

---

# 51. Key Rotation Must Be Idempotent

A rotation operation may fail halfway.

Example:

```text
10,000 item envelopes
```

must not become unrecoverable if:

```text
rotation stops at item 5,243
```

Therefore rotation needs:

```text
old key version
new key version
migration state
per-envelope migration status
retry capability
```

Old keys must remain usable until migration completes.

---

# 52. Two-Phase Key Rotation

Preferred model:

```text
Phase 1
    Generate new key
    Begin writing new objects using it

Phase 2
    Rewrap historical envelopes
    Verify migration
    Retire old key
```

Only after verification:

```text
old key may become RETIRED
```

---

# 53. Destruction

A key may become:

```text
DESTROYED
```

only when:

- No active object depends on it
- Migration has been verified
- Retention policy allows destruction
- Backup implications have been considered

Key destruction must be auditable.

---

# 54. Backup Interaction

Server backups contain:

```text
ciphertext
key envelopes
lifecycle metadata
```

They do not contain plaintext keys.

However, restoring an old backup could restore:

```text
old encrypted key envelopes
old revoked sessions
old lifecycle metadata
```

Therefore restore procedures must reconcile security state after restoration.

---

# 55. Recovery After Database Restore

A restored database must not blindly reactivate:

```text
revoked devices
revoked sessions
retired memberships
compromised key versions
```

Critical revocation state may eventually require an independent append-only security ledger or equivalent mechanism.

---

# 56. Server-Controlled Downgrade

A malicious server might attempt:

```text
"Use old key version"
```

Clients must reject unsafe downgrade attempts.

Clients must persist enough trusted state to detect suspicious rollback where possible.

This will be expanded in the sync protocol.

---

# 57. Memory Policy

When vault locks:

```text
ARK
PVK
CKs
IKs
AKs
decrypted payloads
```

must no longer remain intentionally reachable from application state.

Crypto Core should minimize copies.

Native implementations should zero mutable key buffers where practical.

---

# 58. Client Lock State

The client has explicit states:

```text
SIGNED_OUT
AUTHENTICATED_LOCKED
UNLOCKED
```

These must remain distinct.

### SIGNED_OUT

No authenticated server session.

### AUTHENTICATED_LOCKED

Server session exists.

Vault keys unavailable.

### UNLOCKED

ARK available in client memory.

Vault decryption allowed.

---

# 59. Security Benefit

This enables scenarios such as:

```text
Session stolen
      ↓
attacker downloads ciphertext
      ↓
ARK unavailable
      ↓
vault remains encrypted
```

Authentication compromise and vault compromise are therefore not automatically equivalent.

---

# 60. Sensitive Operations Requiring Unlock

Examples:

```text
View secret
Create secret
Update secret
Export vault
Create recovery material
Enroll trusted device
Share collection
Rotate keys
```

Some operations should additionally require:

```text
reauthentication
```

even when vault is already unlocked.

---

# 61. Crypto-Core Ownership

Only Crypto Core may:

```text
generate keys
derive keys
wrap keys
unwrap keys
encrypt items
decrypt items
create envelopes
parse crypto formats
perform migrations
```

Application business logic must not manipulate raw cryptographic primitives directly.

---

# 62. Logging Policy

The following values are prohibited from logging:

```text
Master Password
Account Secret
MPK
MKEK
ARK
PVK
IK
AK
PRK
USK
CK
plaintext vault data
plaintext attachment data
```

Logs may reference opaque IDs:

```text
keyId
keyVersion
itemId
rotationJobId
```

---

# 63. Metrics Policy

Allowed:

```text
rotation duration
envelope count
crypto operation failures
KDF timing
ciphertext size
```

Forbidden:

```text
key bytes
plaintext
password length tied to identity
recovery secrets
secret metadata
```

---

# 64. V1 Key Lifecycle Scope

V1 must implement:

```text
Account Secret
Master Password
MPK
MKEK
ARK
PVK
IK
PRK
```

V1 may defer:

```text
AK
USK/UPK
CK
DRK
DSK
ORK
```

but the database and protocol must leave room for them.

---

# 65. V1 Unlock Flow

```text
Account Authentication
        ↓
Retrieve:
    KDF parameters
    Wrapped ARK
        ↓
User enters Master Password
        +
Account Secret available
        ↓
Argon2id
        ↓
MPK
        ↓
HKDF
        ↓
MKEK
        ↓
Decrypt ARK
        ↓
Decrypt PVK
        ↓
Vault Unlocked
```

---

# 66. V1 Account Creation Flow

```text
User chooses Master Password
        ↓
Client generates:
    Account Secret
    KDF Salt
    ARK
    PVK
    PRK
        ↓
derive MPK/MKEK
        ↓
wrap ARK with MKEK
        ↓
wrap ARK with Recovery KEK
        ↓
wrap PVK with ARK
        ↓
send ciphertext/envelopes to server
        ↓
generate Recovery Kit
```

---

# 67. V1 Item Creation Flow

```text
User creates item
        ↓
Crypto Core generates IK
        ↓
Encrypt payload with IK
        ↓
Wrap IK with PVK
        ↓
Send:
    ciphertext
    IK envelope
    revision metadata
```

Backend never sees plaintext.

---

# 68. V1 Password Change

```text
Unlock ARK
      ↓
User chooses new Master Password
      ↓
Generate new KDF salt
      ↓
derive new MPK
      ↓
derive new MKEK
      ↓
wrap existing ARK
      ↓
atomically replace password envelope
```

PVK and vault items remain unchanged.

---

# 69. V1 Recovery Flow

```text
User authenticates/re-establishes identity
      ↓
Provides Recovery Key
      ↓
Account Secret obtained from Recovery Kit
      ↓
derive Recovery KEK
      ↓
unwrap ARK
      ↓
choose new Master Password
      ↓
new KDF salt
      ↓
new MKEK
      ↓
new password ARK envelope
      ↓
rotate PRK
      ↓
issue new Recovery Kit
```

---

# 70. Security Invariant

At no point should this be possible:

```text
Backend
   ↓
Database
   ↓
ARK
   ↓
Vault Plaintext
```

Without user-controlled secret material.

---

# 71. Completion Criteria

This key lifecycle is sufficient to begin database design when:

- Every V1 secret has an owner
- Every key has a protection mechanism
- Rotation behavior is documented
- Recovery path is documented
- Compromise scope is documented
- Device and sharing extensions are anticipated
- Key versions are explicit
- Lock/unlock state is explicit
- Server plaintext boundaries are explicit

---

# 72. Next Artifact

Next:

```text
05_SYSTEM_ARCHITECTURE.md
```

followed immediately by:

```text
06_DATABASE_SCHEMA.md
```

The architecture document will define:

```text
Web Client
Crypto Core
API
Identity Module
Vault Module
Sync Module
Device Module
Audit Module
PostgreSQL
Redis
Object Storage
KMS
```

and, critically, which side of the client/server boundary owns each operation.
