# Enterprise Password Manager

## Cryptographic Architecture

**Status:** Draft v0.1
**Protocol Version:** 1
**Security Model:** Zero-Knowledge
**Review Requirement:** External cryptographic review required before production GA.

---

# 1. Objective

Define the cryptographic system responsible for protecting:

- Personal vaults
- Vault items
- Attachments
- Device access
- Recovery
- Shared vaults
- Organization collections
- Future enterprise recovery

The architecture must preserve the primary invariant:

> Possession of the database, backend infrastructure, or backups alone must not be sufficient to decrypt user vault contents.

---

# 2. Design Principles

## 2.1 No custom cryptography

We design protocols and key relationships.

We do not implement cryptographic primitives.

All primitives must come from mature reviewed libraries.

---

## 2.2 Key separation

Every cryptographic key has exactly one defined purpose.

A key used for:

```text
vault encryption
```

must never also be used for:

```text
authentication
signing
device enrollment
recovery
```

---

## 2.3 Envelope encryption

Large amounts of data are not directly encrypted with master-password-derived material.

Instead:

```text
Master Password
      ↓
Password KDF
      ↓
Master KEK
      ↓
wraps
      ↓
Account Root Key
      ↓
wraps
      ↓
Vault / Collection Keys
      ↓
wrap
      ↓
Item Data Keys
      ↓
encrypt
      ↓
Vault Data
```

---

# 3. Candidate Primitive Suite

The initial protocol candidate is:

```text
Password KDF
    Argon2id

Symmetric AEAD
    AES-256-GCM

Subkey derivation
    HKDF-SHA-256

Hash
    SHA-256

Randomness
    OS CSPRNG

Future asymmetric sharing
    HPKE

Future device signatures
    Ed25519 or equivalent reviewed scheme
```

Argon2id is specified by RFC 9106; the RFC includes a 64 MiB, three-pass configuration as its second recommended option for memory-constrained environments. Final product parameters will be benchmarked rather than blindly hardcoded.

AES-GCM provides authenticated encryption and is supported by the Web Crypto API. Its IV must be unique for every encryption operation performed with a given key; a 96-bit IV is the standard recommended size.

For future user-to-user key distribution, HPKE is the preferred protocol candidate rather than inventing our own ECIES-like construction. RFC 9180 defines HPKE using combinations of a KEM, KDF, and AEAD.

---

# 4. Cryptographic Objects

The system will initially recognize these key types.

```text
MP      Master Password

MPK     Master Password Key
MKEK    Master Key Encryption Key

ARK     Account Root Key

PVK     Personal Vault Key
CK      Collection Key
IK      Item Data Key
AK      Attachment Data Key

PRK     Personal Recovery Key

UPK     User Public Sharing Key
USK     User Private Sharing Key

DRK     Device Root Key
DSK     Device Signing Key

ORK     Organization Recovery Key
```

Not every key exists in V1.

The naming exists now to prevent incompatible architecture later.

---

# 5. Master Password

The Master Password is human-generated.

It must never:

- Be stored by the backend
- Be logged
- Be transmitted to analytics
- Become an encryption key directly
- Be reused directly as authentication material

The client performs password key derivation.

Conceptually:

```text
Master Password
      +
KDF Salt
      +
KDF Parameters
      ↓
   Argon2id
      ↓
      MPK
```

`MPK` is an intermediate key.

Application code should not directly use it.

---

# 6. Password KDF

Each account receives a cryptographically random salt.

Minimum:

```text
128-bit salt
```

The server may store:

```json
{
  "algorithm": "argon2id",
  "version": 1,
  "salt": "...",
  "memoryKiB": 65536,
  "iterations": 3,
  "parallelism": 4
}
```

This example is illustrative.

Final parameters are determined through benchmarking.

The client must enforce a minimum acceptable security floor and must reject maliciously weak server-provided parameters.

This is important because a compromised backend must not be able to send:

```text
memory = 8 KiB
iterations = 1
```

and silently downgrade password protection.

---

# 7. Subkey Derivation

Argon2id produces:

```text
MPK
```

We use explicit domain separation for downstream keys.

Example:

```text
MKEK = HKDF(
    MPK,
    info = "credential-manager/mkek/v1"
)
```

Future derivations must use independent labels.

Example:

```text
credential-manager/mkek/v1
credential-manager/export/v1
credential-manager/device-bootstrap/v1
```

Never:

```text
same derived bytes for multiple purposes
```

---

# 8. Account Root Key

The **Account Root Key (ARK)** is the central root of the user's vault hierarchy.

Properties:

```text
Random
256 bits
Generated client-side
Never derived from password
Never stored plaintext server-side
```

Creation:

```text
CSPRNG
   ↓
256 random bits
   ↓
ARK
```

---

# 9. Protecting the Account Root Key

The client derives:

```text
Master Password
      ↓
Argon2id
      ↓
MPK
      ↓
HKDF
      ↓
MKEK
```

Then:

```text
ARK
 ↓
AES-256-GCM using MKEK
 ↓
Wrapped ARK
```

The backend stores only:

```text
Wrapped ARK
IV
Authentication Tag
KDF Salt
KDF Parameters
Protocol Version
```

It does not store:

```text
MKEK
MPK
ARK
Master Password
```

---

# 10. Root Key Envelope

Example serialized object:

```json
{
  "protocolVersion": 1,
  "type": "account-root-key-envelope",
  "kdf": {
    "algorithm": "argon2id",
    "salt": "...",
    "memoryKiB": 65536,
    "iterations": 3,
    "parallelism": 4
  },
  "encryption": {
    "algorithm": "AES-256-GCM",
    "iv": "...",
    "ciphertext": "..."
  }
}
```

The actual binary serialization format will be defined separately.

---

# 11. Additional Authenticated Data

AEAD operations must bind ciphertext to its context.

Example AAD:

```text
protocolVersion
objectType
objectId
ownerId
containerId
keyVersion
revision
```

Example conceptually:

```text
v1|vault-item|item_123|user_456|vault_789|key_4|revision_17
```

This helps prevent a valid ciphertext from being moved into an unintended context.

AAD must contain no secret material.

---

# 12. Personal Vault Key

The Account Root Key does not directly encrypt vault contents.

Instead:

```text
ARK
 ↓ wraps
PVK
```

`PVK`:

```text
Personal Vault Key
256-bit random
```

The server stores:

```text
Encrypted PVK
```

The hierarchy becomes:

```text
Master Password
      ↓
     MKEK
      ↓
     ARK
      ↓
     PVK
```

---

# 13. Why Separate ARK and PVK

This allows future support for multiple independent vaults:

```text
ARK
 ├── Personal Vault Key
 ├── Work Vault Key
 ├── Archive Vault Key
 └── Private Key Protection Key
```

without deriving every structure directly from the password.

---

# 14. Item Encryption

Every item revision receives its own random **Item Data Key**.

```text
IK = random 256-bit key
```

Then:

```text
Item Plaintext
      ↓
AES-256-GCM(IK)
      ↓
Encrypted Item Payload
```

The Item Key itself is wrapped:

```text
IK
 ↓
PVK / Collection Key
 ↓
Wrapped IK
```

Stored server-side:

```text
Encrypted Item Payload
Wrapped IK
IVs
Versions
Revision Metadata
```

---

# 15. Item Structure

Conceptually:

```json
{
  "id": "item_uuid",
  "protocolVersion": 1,
  "revision": 7,
  "containerId": "vault_uuid",
  "keyEnvelope": {
    "keyVersion": 3,
    "iv": "...",
    "ciphertext": "..."
  },
  "payload": {
    "iv": "...",
    "ciphertext": "..."
  }
}
```

The payload may contain:

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

That entire structure is encrypted client-side.

The backend does not need to understand it.

---

# 16. Item Metadata

Prefer:

```text
Encrypted:
    name
    username
    URL
    notes
    credential fields
    TOTP
    custom fields
```

Server-readable metadata should remain minimal:

```text
itemId
containerId
revision
createdAt
updatedAt
encryptedSize
deletion state
```

Even `item type` should remain encrypted unless a strong server-side requirement appears.

---

# 17. Item Revisions

Every mutation produces a new revision.

Example:

```text
revision 41
    ↓
revision 42
```

Recommended design:

```text
new revision
      ↓
fresh Item Key
      ↓
fresh AEAD IV
```

This minimizes cross-revision cryptographic coupling.

---

# 18. Nonce / IV Management

Application code must never manually choose cryptographic IVs.

Crypto Core provides:

```text
encrypt()
```

not:

```text
encrypt(key, userProvidedNonce)
```

For AES-GCM:

```text
96-bit random IV
```

generated by CSPRNG.

The IV is stored next to the ciphertext.

It is not secret.

Nonce reuse under the same AES-GCM key is forbidden.

Using fresh item keys for item revisions further reduces the probability and consequence of accidental reuse.

---

# 19. Attachments

Every attachment receives an independent:

```text
Attachment Key (AK)
```

generated randomly.

```text
Attachment
      ↓
AK
      ↓
Encrypted Blob
```

Then:

```text
AK
 ↓
IK or container key
 ↓
Wrapped AK
```

For large attachments we will later define:

```text
chunked authenticated encryption
```

rather than loading an entire multi-gigabyte file into memory.

Attachment encryption requires a separate protocol specification.

---

# 20. Authentication vs Vault Unlock

These remain strictly separate.

## Account authentication

Answers:

```text
May this user establish an authenticated server session?
```

## Vault unlocking

Answers:

```text
Can this client obtain ARK?
```

A valid authenticated session does not automatically imply possession of ARK.

---

# 21. Preferred Authentication Direction

The long-term authentication architecture should prioritize:

```text
Passkeys / WebAuthn
```

with a carefully reviewed password fallback.

A password-authenticated protocol such as OPAQUE may be evaluated separately.

Authentication protocol decisions must not modify the vault encryption hierarchy.

---

# 22. Login on a New Device

Conceptual flow:

```text
User
 ↓
Authenticate Account
 ↓
Server returns:
    Wrapped ARK
    KDF parameters
    encrypted vault metadata
 ↓
Client asks for Master Password
 ↓
Argon2id
 ↓
MKEK
 ↓
Decrypt Wrapped ARK
 ↓
ARK
 ↓
Decrypt PVK
 ↓
Decrypt Item Keys
 ↓
Decrypt requested items
```

The backend never performs the decryption.

---

# 23. Wrong Master Password

If an incorrect password is entered:

```text
wrong password
      ↓
wrong MKEK
      ↓
AEAD authentication fails
```

The client reports:

```text
Unable to unlock vault
```

without exposing unnecessary cryptographic information.

---

# 24. Password Change

Changing the Master Password must not require re-encrypting every vault item.

Flow:

```text
Old Master Password
      ↓
Old MKEK
      ↓
Decrypt ARK

New Master Password
      ↓
New Argon2id Salt
      ↓
New MKEK
      ↓
Re-wrap same ARK
```

Therefore:

```text
1 ARK envelope changes
```

instead of:

```text
50,000 vault items
```

---

# 25. KDF Upgrade

Suppose we later increase Argon2 parameters.

We can perform:

```text
old KDF
 ↓
old MKEK
 ↓
ARK
 ↓
new MKEK
 ↓
new ARK envelope
```

No vault-item re-encryption is required.

---

# 26. Personal Recovery Key

Account recovery must not create a server master key.

During account creation the client generates:

```text
PRK = 256-bit random recovery secret
```

The user receives it through an explicit recovery artifact.

For example:

```text
XXXX-XXXX-XXXX-XXXX-...
```

or another error-resistant encoding.

---

# 27. Recovery Envelope

The PRK produces recovery wrapping material using a dedicated derivation context.

Conceptually:

```text
PRK
 ↓
HKDF
 ↓
Recovery KEK
```

Then:

```text
ARK
 ↓
Recovery KEK
 ↓
Recovery ARK Envelope
```

Server stores:

```text
Recovery ARK Envelope
```

but never:

```text
PRK
```

---

# 28. Recovery Flow

```text
User loses Master Password
        ↓
Identity Recovery
        ↓
Provide PRK
        ↓
Client derives Recovery KEK
        ↓
Decrypt ARK
        ↓
Choose new Master Password
        ↓
Generate new MKEK
        ↓
Re-wrap ARK
```

This restores vault access without a global vendor decryption key.

---

# 29. Lost Master Password + Lost PRK

If the user loses:

```text
Master Password
+
Recovery Key
+
all trusted devices
```

the personal zero-knowledge vault may be cryptographically unrecoverable.

That is an intentional consequence of the security model.

We must communicate it clearly during onboarding.

---

# 30. Trusted Device Keys

Native applications will eventually generate a:

```text
Device Root Key (DRK)
```

inside secure OS storage.

Examples:

```text
Apple Keychain / Secure Enclave
Android Keystore
Windows Hello / TPM
```

ARK may then have a device-specific envelope:

```text
ARK
 ↓
DRK
 ↓
Device ARK Envelope
```

allowing secure fast unlock.

---

# 31. Biometrics

Biometrics must not encrypt vault data directly.

Instead:

```text
Face ID / fingerprint / Windows Hello
            ↓
OS releases DRK
            ↓
DRK unwraps ARK
```

This keeps biometric policy separate from vault encryption.

---

# 32. Web Client Persistence

The web application requires stricter rules.

Initial policy:

> Do not persist plaintext ARK or decrypted vault contents across browser restarts.

Web-specific trusted-device functionality requires an independent security review.

Browser storage should be considered hostile compared with hardware-backed native storage.

---

# 33. User Sharing Keys

For future sharing, each user receives an asymmetric key pair:

```text
UPK = User Public Key
USK = User Secret Key
```

Generated client-side.

The server may store:

```text
UPK
Encrypted USK
```

but never plaintext:

```text
USK
```

The USK is protected under user-controlled key material.

---

# 34. Why Public-Key Cryptography Is Needed

Suppose Daniel shares a collection with Alice.

The server should be able to transport access without decrypting it.

Conceptually:

```text
Collection Key
      ↓
encrypted to
Alice Public Key
      ↓
Encrypted Collection Key
```

Alice uses:

```text
Alice Private Key
```

to recover the Collection Key.

---

# 35. Sharing Protocol Candidate

Rather than implementing our own:

```text
ECDH + HKDF + AES
```

construction, the preferred candidate is:

```text
HPKE
```

defined in RFC 9180.

The exact HPKE ciphersuite must be frozen only after:

- Browser interoperability testing
- Native interoperability testing
- Library review
- External cryptographic review

---

# 36. Collection Keys

Organization or shared collections use:

```text
CK = Collection Key
```

randomly generated client-side.

Items belonging to the collection use:

```text
CK
 ↓ wraps
IK
```

Members receive access to CK through individual encrypted key envelopes.

Example:

```text
CK
 ├── encrypted for Alice
 ├── encrypted for Bob
 ├── encrypted for Charlie
 └── optionally encrypted for approved recovery authority
```

---

# 37. Removing a Member

When Alice is removed:

```text
CK version 4
       ↓
rotate
       ↓
CK version 5
```

Remaining item keys can be rewrapped:

```text
IK
 ↓
CK v5
```

without decrypting every item payload.

Alice receives no CK v5 envelope.

---

# 38. Important Revocation Limitation

Key rotation cannot erase information Alice already decrypted.

If Alice previously knew:

```text
Production Database Password
```

cryptography cannot make her forget it.

For highly sensitive credentials, membership removal should trigger:

```text
credential rotation
```

in the external system itself.

---

# 39. Organization Recovery

Enterprise recovery must not create a universal vendor key.

An organization may optionally configure:

```text
Organization Recovery Public Key
```

Organization-owned collection keys may additionally be encrypted to that recovery authority.

Conceptually:

```text
CK
 ├── Member A
 ├── Member B
 └── Organization Recovery
```

---

# 40. Personal vs Organization Recovery

Critical invariant:

```text
Personal Vault
        ≠
Organization Vault
```

Organization recovery must not silently provide access to personal vault keys.

Any managed-account exception must be:

- Explicit
- Visible
- Documented
- Auditable
- Cryptographically distinguishable

---

# 41. Key Versions

Every wrapped key stores:

```text
keyVersion
```

Example:

```json
{
  "keyId": "collection-key",
  "version": 7,
  "algorithm": "AES-256-GCM",
  "iv": "...",
  "ciphertext": "..."
}
```

Clients must understand which key version encrypted each envelope.

---

# 42. Protocol Versions

Protocol version and key version are different.

Example:

```text
protocolVersion = 2
collectionKeyVersion = 17
itemRevision = 83
```

These values must never be conflated.

---

# 43. Cryptographic Agility

Serialized data must identify the algorithm suite.

Example:

```json
{
  "protocolVersion": 1,
  "suite": "PM-AESGCM-ARGON2ID-1"
}
```

A future version could migrate to:

```text
PM-NEW-SUITE-2
```

without guessing how legacy ciphertext was generated.

---

# 44. Algorithm Downgrade Protection

The server must not be able to silently instruct the client to switch from:

```text
secure suite
```

to:

```text
legacy weak suite
```

Clients must contain:

```text
minimum accepted protocol
minimum KDF security
allowed algorithm suites
```

Downgrade attempts must fail closed.

---

# 45. Randomness

All generation of:

```text
ARK
PVK
CK
IK
AK
PRK
IVs
private keys
session secrets
```

must use an OS-backed cryptographically secure random number generator.

No security-sensitive code may use:

```text
Math.random()
pseudo-random application helpers
timestamp-based randomness
UUID randomness as key material
```

unless the UUID implementation is used only for identifiers rather than cryptographic secrets.

---

# 46. Memory Handling

When plaintext secrets or key material must exist:

- Minimize lifetime
- Avoid unnecessary copies
- Avoid serialization where unnecessary
- Clear mutable buffers where supported
- Never place them in logs
- Never place them in crash reports
- Never send them to telemetry

JavaScript memory cannot provide the same deterministic zeroization guarantees as lower-level environments.

This is one reason to isolate sensitive operations inside Crypto Core wherever practical.

---

# 47. Crypto Core API

Application code should interact with high-level operations.

Allowed style:

```text
createAccountKeyMaterial()
unlockAccount()
createVault()
encryptItem()
decryptItem()
rotateCollectionKey()
createRecoveryEnvelope()
shareCollection()
```

Avoid exposing unnecessarily low-level operations such as:

```text
aesEncrypt()
aesDecrypt()
createNonce()
rawECDH()
```

to general application code.

---

# 48. Backend Knowledge

For a personal item the backend may know:

```text
User ID
Vault ID
Item ID
Revision
Encrypted size
Timestamps
Ciphertext
Wrapped keys
```

It should not know:

```text
GitHub
daniel@example.com
MyPassword123
github.com
TOTP seed
Secret notes
```

---

# 49. Database Breach Result

A complete database breach should produce data resembling:

```text
user_123

KDF:
    salt
    parameters

Root:
    encrypted ARK

Vault:
    encrypted PVK

Item:
    encrypted IK
    encrypted payload
```

The attacker should still require the user's secret material to obtain plaintext.

---

# 50. Offline Password Attacks

The encrypted ARK envelope allows a password guess to be tested offline.

Therefore master-password strength and Argon2id cost remain extremely important.

Before GA we should additionally evaluate an optional:

```text
Account Secret
```

generated randomly during onboarding and stored only on trusted devices/recovery material.

Conceptually:

```text
Master Password
      +
Account Secret
      ↓
Password KDF
```

This can significantly strengthen resistance against database-only offline attacks because the second component has high entropy.

It would, however, change onboarding, recovery, and new-device enrollment.

Therefore it is a deliberate future protocol decision, not something to introduce casually.

---

# 51. Authentication Hardening

An advanced password authentication protocol may reduce server exposure of password-derived authentication material.

Potential candidate:

```text
OPAQUE
```

However:

- It does not replace vault encryption.
- It does not remove the need for a strong vault KDF.
- Library maturity must be reviewed.
- It requires its own protocol document.
- It should not be implemented from scratch.

---

# 52. Cryptographic Boundaries

The following modules may handle plaintext:

```text
Crypto Core
Unlocked client memory
Explicit clipboard operation
Explicit autofill operation
Explicit export operation
```

The following must not:

```text
Backend API
PostgreSQL
Redis
Object Storage
Backups
Server Logs
Analytics
Telemetry
SIEM
Email systems
Support systems
```

---

# 53. Production Crypto Review Gates

Before production release, require:

### Gate 1

Internal protocol review.

### Gate 2

Cross-platform cryptographic test vectors.

### Gate 3

Fuzz testing of serialization/parsing.

### Gate 4

Independent security review.

### Gate 5

Specialized external cryptographic review.

### Gate 6

Documented migration strategy.

---

# 54. Required Test Vectors

Every crypto operation must have deterministic interoperability vectors.

Example:

```text
Protocol Version
Input Key
Salt
KDF Parameters
AAD
IV
Plaintext
Expected Ciphertext
Expected Tag
```

Shared vectors must pass identically across future:

```text
Rust
WASM
Web
Desktop
iOS
Android
```

---

# 55. Key Hierarchy Summary

```text
                         MASTER PASSWORD
                               │
                               ▼
                            Argon2id
                               │
                               ▼
                              MPK
                               │
                               ▼
                          HKDF / MKEK
                               │
                               ▼
                    ┌────────────────────┐
                    │ Encrypted ARK      │
                    └────────────────────┘
                               │
                            unwrap
                               │
                               ▼
                              ARK
                        ┌──────┼─────────┐
                        │      │         │
                        ▼      ▼         ▼
                       PVK    USK      Other Vault Keys
                        │
                ┌───────┼────────┐
                │       │        │
                ▼       ▼        ▼
               IK      IK       IK
                │
          ┌─────┴─────┐
          │           │
          ▼           ▼
      Item Data       AK
                      │
                      ▼
                 Attachment
```

---

# 56. Sharing Hierarchy Summary

```text
                     Collection Key
                          │
               ┌──────────┼──────────┐
               │          │          │
               ▼          ▼          ▼
            Item Key   Item Key   Item Key


Collection Key
      │
      ├── HPKE → Alice Public Key
      │
      ├── HPKE → Bob Public Key
      │
      └── HPKE → Charlie Public Key
```

The server transports envelopes.

It does not recover the Collection Key.

---

# 57. Recovery Hierarchy Summary

```text
Master Password ──────► MKEK ─────────┐
                                      │
                                      ▼
                                     ARK
                                      ▲
                                      │
Recovery Key ─────► Recovery KEK ─────┘
```

Two independent ways may unwrap the same root key.

Neither secret is stored by the backend.

---

# 58. Decisions Frozen for V1

The following architectural decisions are considered baseline:

```text
Client-side encryption
Random Account Root Key
Envelope encryption
Per-item Data Keys
Authenticated encryption
Explicit AAD
Versioned ciphertext
Separated authentication and vault unlock
Recovery without vendor master key
No plaintext secrets server-side
```

---

# 59. Decisions Not Yet Frozen

Must be validated before implementation or GA:

```text
Exact Argon2id parameters
Exact crypto library
Rust/WASM boundary
HPKE ciphersuite
Device key scheme
Device signing scheme
Account Secret adoption
OPAQUE adoption
Web trusted-device mechanism
Chunked attachment encryption
Enterprise recovery protocol
FIPS compatibility strategy
```

---

# 60. Next Artifact

The next document is:

```text
04_KEY_HIERARCHY_AND_LIFECYCLE.md
```

It will define each key as an independent asset:

```text
Who creates it?
Where does it exist?
Where is it stored?
What encrypts it?
When is it loaded?
When is it deleted?
When is it rotated?
Who can receive it?
What happens when it is compromised?
```

Only after that document is stable should we design the database schema.
