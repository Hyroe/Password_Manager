# Enterprise Password Manager

## Threat Model

**Status:** Draft v0.1
**Security Model:** Zero-Knowledge Credential Manager
**Purpose:** Identify protected assets, trust boundaries, attacker capabilities, major attack scenarios, required controls, and accepted residual risks.

---

# 1. Security Objective

The primary security objective is:

> A compromise of the backend, database, backups, or infrastructure must not be sufficient to decrypt user vault contents.

The system must minimize the consequences of compromise rather than assuming compromise will never occur.

Security controls must therefore assume that individual system components may eventually fail.

---

# 2. Protected Assets

## 2.1 Critical Secrets

Highest sensitivity:

- Passwords
- TOTP seeds
- API keys
- Private SSH keys
- Private cryptographic keys
- Recovery keys
- Payment credentials
- Authentication tokens
- Session secrets
- Vault encryption keys
- Collection encryption keys
- Attachment encryption keys

---

## 2.2 Sensitive Metadata

Examples:

- Item names
- Websites
- Usernames
- Account identifiers
- Folder names
- Organization names
- Secret categories
- Credential creation timestamps
- Credential usage information
- Sharing relationships

Sensitive metadata should remain encrypted whenever server visibility is not operationally required.

---

## 2.3 Identity Data

Examples:

- Email
- User ID
- Organization membership
- Device registrations
- Authentication methods
- Security policies
- Login history
- IP addresses
- Session metadata

Some identity information must remain server-readable.

It must still be protected through access control, encryption at rest, logging policies, and retention limits.

---

# 3. Trust Boundaries

Primary trust boundaries:

```text
User
 │
 ▼
Client Application
 │
 ├── Crypto Core
 │
 ├── Local Encrypted Storage
 │
 └── Session State
 │
 ▼
Internet
 │
 ▼
API Boundary
 │
 ▼
Backend
 │
 ├── Identity
 │
 ├── Vault
 │
 ├── Sync
 │
 ├── Organization
 │
 └── Audit
 │
 ▼
Data Layer
 │
 ├── PostgreSQL
 │
 ├── Redis
 │
 ├── Object Storage
 │
 └── Backups
```

Every boundary must be treated as potentially hostile.

---

# 4. Trust Assumptions

## TA-001

The user's device is trusted only while it has not been compromised.

## TA-002

The backend is not trusted with plaintext vault data.

## TA-003

The database is not trusted with plaintext vault data.

## TA-004

Cloud infrastructure administrators are not trusted with plaintext vault data.

## TA-005

Network infrastructure is not trusted.

Transport security is required even though application-level encryption exists.

## TA-006

Browser execution environments are considered higher risk than native secure hardware.

## TA-007

Organization administrators are trusted only for explicitly granted administrative capabilities.

They are not automatically trusted with personal secrets.

## TA-008

External identity providers authenticate users but must not automatically gain access to vault decryption keys.

---

# 5. Attacker Profiles

## A1 — Remote Unauthenticated Attacker

Capabilities:

- Reach public APIs
- Send arbitrary network requests
- Enumerate endpoints
- Perform credential stuffing
- Perform brute-force attempts
- Exploit exposed vulnerabilities

Primary goals:

- Account takeover
- Data theft
- Service disruption

---

## A2 — Authenticated Malicious User

Capabilities:

- Own valid account
- Access legitimate API functionality
- Manipulate identifiers and payloads
- Attempt privilege escalation
- Attempt unauthorized vault access

Primary goals:

- Access another user's data
- Access another organization
- Modify shared resources
- Abuse synchronization or sharing

---

## A3 — Database Attacker

Capabilities:

- Read database contents
- Possibly modify database contents
- Read historical snapshots

Must not be able to:

- Recover vault plaintext
- Recover master passwords
- Recover unwrapped vault keys

---

## A4 — Backend Compromise

Capabilities:

- Execute code inside backend environment
- Access database
- Access backend environment secrets
- Forge API responses
- Observe incoming requests

Expected limitation:

The backend still should not possess long-term cryptographic material sufficient to decrypt stored vault data.

This attack becomes more dangerous when an active client communicates with the compromised backend.

---

## A5 — Cloud Infrastructure Administrator

Capabilities may include:

- Snapshot servers
- Inspect storage
- Access infrastructure configuration
- Restart workloads
- Access network configuration

Must not automatically obtain plaintext vault secrets.

---

## A6 — Malicious Organization Administrator

Capabilities:

- Manage legitimate organization resources
- Change policies
- Add or remove members
- Potentially control organization-managed recovery

Must not:

- Gain silent access to unrelated personal vaults
- Circumvent documented cryptographic permissions
- Decrypt resources outside explicitly granted organization scope

---

## A7 — Compromised Client Device

Capabilities:

- Read process memory
- Capture keyboard input
- Capture screenshots
- Read local storage
- Intercept clipboard
- Modify application execution

If the vault is unlocked, this attacker may gain plaintext access.

This is an accepted fundamental limitation.

---

## A8 — Malicious Browser Context

Capabilities:

- Hostile websites
- DOM manipulation
- Phishing
- iframe abuse
- extension messaging abuse
- malicious injected JavaScript

Especially relevant for:

- Web application
- Browser extension
- Autofill

---

## A9 — Supply Chain Attacker

Targets:

- npm packages
- Rust crates
- CI/CD
- build environment
- containers
- GitHub Actions
- release artifacts

Primary goal:

Inject code capable of stealing secrets during legitimate execution.

---

## A10 — Malicious Insider

Potential access:

- Source code
- Production infrastructure
- Support systems
- Logs
- Administrative dashboards

The system must minimize the amount of sensitive information accessible to individual employees.

---

# 6. Primary Threat Scenarios

---

# T01 — Database Exfiltration

## Scenario

An attacker obtains a complete PostgreSQL dump.

Potentially exposed:

- User identities
- Ciphertext
- Encrypted key material
- Device metadata
- Organization metadata
- Audit history

## Required Property

The database alone must not be sufficient to decrypt vault contents.

## Controls

- Client-side encryption
- Strong KDF
- Random vault keys
- Encrypted key wrapping
- No plaintext secrets
- No master passwords
- Database encryption at rest
- Least-privilege database access
- Backup encryption

## Residual Risk

Metadata that must remain server-readable may be exposed.

---

# T02 — Backup Compromise

## Scenario

An attacker steals production backups.

## Controls

Same cryptographic protection as the live database.

Additional controls:

- Backup encryption
- Independent backup credentials
- Restricted restore permissions
- Immutable backup storage
- Backup access auditing
- Retention policies

## Security Requirement

A backup must never become a weaker security boundary than production.

---

# T03 — Backend Server Compromise

## Scenario

An attacker obtains arbitrary code execution on the API server.

## Attacker Can Potentially

- Read backend environment variables
- Query databases
- Modify API responses
- Steal active authentication tokens
- Modify encrypted vault data
- Serve malicious client instructions

## Attacker Must Not Automatically Gain

- Master passwords
- Persistent vault root keys
- Decrypted vault database contents

## Controls

- Zero-knowledge cryptographic design
- No plaintext vault processing server-side
- KMS-protected infrastructure secrets
- Strong service isolation
- Least privilege
- Egress controls
- Signed client releases
- CSP for web client
- Runtime monitoring

## Important Limitation

A compromised backend may attempt to attack future client interactions.

Zero-knowledge protects stored data more strongly than it protects an actively compromised delivery channel.

---

# T04 — Credential Stuffing

## Scenario

Attacker uses email/password pairs leaked from other services.

## Controls

- Rate limiting
- IP reputation
- Progressive throttling
- MFA
- Passkeys
- WebAuthn
- Credential stuffing detection
- Login notifications
- Session visibility

---

# T05 — Offline Master Password Attack

## Scenario

An attacker steals:

- encrypted root key
- KDF parameters
- salt

and attempts offline password guessing.

## Controls

- Argon2id
- Unique random salts
- Strong default parameters
- Client-specific KDF calibration
- Minimum acceptable KDF floor
- Strong master-password guidance
- Optional password strength estimation

## Residual Risk

Weak master passwords remain vulnerable to sufficiently powerful offline attackers.

The system cannot cryptographically transform a very weak human password into a high-entropy secret.

---

# T06 — Session Theft

## Scenario

Attacker steals an authenticated session.

## Potential Consequences

- Download encrypted vault
- Modify server-side metadata
- Perform actions authorized by session
- Potentially synchronize malicious state

## Controls

- Short-lived access credentials
- Secure refresh/session mechanism
- Session rotation
- Device binding where appropriate
- Reauthentication for sensitive actions
- Session revocation
- Active device visibility
- Suspicious-login detection

## Important Distinction

An authenticated server session does not necessarily imply access to decrypted vault data.

---

# T07 — Cross-User Authorization Bypass

## Scenario

User changes:

```text
/vaults/123
```

to:

```text
/vaults/124
```

and receives another user's data.

## Controls

- Server-side authorization on every resource
- No trust in client identifiers
- Ownership checks
- Organization boundary checks
- Deny by default
- Integration tests for cross-tenant access

---

# T08 — Cross-Organization Data Leakage

## Scenario

A user belonging to Organization A attempts to access Organization B resources.

## Controls

Every organization-owned query must be scoped by:

```text
organizationId
+
authenticated identity
+
explicit permission
```

Never depend only on resource IDs.

---

# T09 — XSS Against Web Vault

## Scenario

Attacker executes JavaScript inside the web application.

## Impact

Potentially catastrophic while the vault is unlocked.

The attacker may read decrypted secrets directly from application memory.

## Controls

- Strict Content Security Policy
- No unsafe inline scripts
- Trusted Types where possible
- Strong output encoding
- Sanitization
- Dependency restrictions
- No arbitrary HTML rendering
- Secure templating
- Minimal third-party scripts
- No advertising scripts
- No analytics scripts in sensitive execution contexts

## Security Principle

The unlocked web vault should have an exceptionally small JavaScript trust surface.

---

# T10 — Malicious Third-Party Script

## Scenario

Analytics, support, or monitoring JavaScript is compromised.

## Policy

Third-party scripts should not execute inside the authenticated vault application unless explicitly security-reviewed.

Preferred architecture:

```text
marketing.example.com
```

may use analytics.

```text
vault.example.com
```

should be heavily isolated.

---

# T11 — CSRF

## Scenario

A malicious website attempts authenticated state-changing actions.

## Controls

Depending on authentication architecture:

- SameSite cookies
- CSRF tokens
- Origin validation
- Content-Type restrictions
- No state-changing GET requests

---

# T12 — Clipboard Leakage

## Scenario

A password copied to clipboard remains available to unrelated applications.

## Controls

- Configurable clipboard timeout
- Automatic clearing
- User warnings where OS restrictions apply
- Prefer direct autofill when possible

## Limitation

Clipboard protection depends partly on the operating system.

---

# T13 — Local Vault Theft

## Scenario

Attacker copies local application storage from a lost device.

## Controls

- Local encrypted vault
- Device-bound key protection
- OS keychain / secure storage
- Auto-lock
- Biometric unlock only through protected key material
- Never store plaintext vault cache

---

# T14 — Memory Extraction

## Scenario

Attacker reads RAM while the vault is unlocked.

## Controls

- Minimize plaintext lifetime
- Minimize duplicated secret buffers
- Explicit memory clearing where supported
- Avoid unnecessary serialization
- Lock vault aggressively
- Avoid storing decrypted complete vault where unnecessary

## Residual Risk

On a fully compromised device, memory protection cannot guarantee secrecy.

---

# T15 — Malicious Browser Extension

## Scenario

Another extension has broad page access and steals information from the web vault.

## Controls

- Strong web isolation
- Separate browser extension architecture
- Avoid rendering secrets unnecessarily
- Encourage native clients for higher assurance environments
- Enterprise extension policies where available

---

# T16 — Phishing

## Scenario

User visits:

```text
passw0rd-manager.example
```

instead of the legitimate service.

## Controls

- Passkeys
- WebAuthn
- Verified browser extension
- Domain-bound authentication
- Clear domain UX
- Anti-phishing education
- Signed applications

Passkeys/WebAuthn significantly improve resistance to credential phishing.

---

# T17 — Recovery Abuse

## Scenario

Attacker manipulates account recovery to bypass cryptographic controls.

## Controls

Recovery must be a cryptographic protocol, not only an identity workflow.

Any recovery mechanism must answer:

```text
Who can recover?
What exactly can they recover?
Which key is recovered?
How is authorization proven?
Can recovery access historical data?
Can the organization recover personal secrets?
```

No universal recovery key is allowed.

---

# T18 — Organization Admin Abuse

## Scenario

An administrator attempts to secretly gain access to employee secrets.

## Controls

- Explicit organization key hierarchy
- Clear personal vs organization ownership
- Recovery policy visibility
- Audit logs
- Role separation
- Sensitive-action notifications
- Key rotation after membership changes

---

# T19 — Removed Employee Retains Access

## Scenario

A user is removed from an organization but possesses old keys.

## Important Property

Cryptography cannot make the user forget secrets already seen.

## Required Response

After removal:

- Revoke sessions
- Revoke organization authorization
- Rotate appropriate organization keys
- Prevent access to future secret versions

## Residual Risk

Previously decrypted or copied secrets cannot be remotely erased.

---

# T20 — Malicious Shared-Vault Member

## Scenario

A legitimate member copies organization credentials.

## Controls

- Least privilege
- Collection-level access
- Audit trails
- Sensitive access policies
- Secret rotation when membership changes

## Limitation

A user authorized to view a secret can potentially copy it.

---

# T21 — Sync Replay Attack

## Scenario

Attacker replays an older encrypted object version.

Potential result:

- Restore revoked secret
- Undo password rotation
- Reintroduce stale state

## Controls

- Object versions
- Monotonic revisions
- Server-side revision tracking
- Cryptographically bound version metadata
- Conflict detection

---

# T22 — Rollback Attack

## Scenario

A malicious server gives a client an old but valid encrypted vault snapshot.

## Controls

The protocol should eventually consider:

- Version counters
- Last-known revision
- Signed state
- Device checkpoints

This threat requires explicit treatment in the sync protocol.

---

# T23 — Ciphertext Tampering

## Scenario

Attacker modifies encrypted vault data.

## Controls

Authenticated encryption must make unauthorized modification detectable.

No unauthenticated encryption modes are permitted.

---

# T24 — Nonce Reuse

## Scenario

An implementation accidentally reuses an AEAD nonce with the same key.

## Impact

May catastrophically weaken confidentiality depending on the selected cipher.

## Controls

- Central crypto API
- Nonce generation encapsulated by crypto-core
- No application-managed nonces
- Cryptographic tests
- Fuzzing
- Code review

---

# T25 — Key Reuse Across Domains

## Scenario

The same cryptographic key is reused for unrelated purposes.

Example:

```text
Vault Encryption Key
=
Authentication Key
```

## Controls

Strict key separation.

Keys should have one defined cryptographic purpose.

Where derivation is used, domain separation must be explicit.

---

# T26 — Weak Randomness

## Scenario

Keys are generated using non-cryptographic randomness.

## Controls

Only operating-system CSPRNG-backed cryptographic libraries may generate:

- Keys
- Nonces
- Recovery codes
- Session tokens

No:

```text
Math.random()
```

or equivalent non-CSPRNG mechanism is allowed for security material.

---

# T27 — Secret Logging

## Scenario

Sensitive values reach:

- application logs
- Sentry
- traces
- metrics
- analytics
- error reports

## Controls

- Explicit redaction
- Structured logging
- No request-body logging on secret endpoints
- Security review of observability tooling
- Automated tests for secret leakage

---

# T28 — CI/CD Compromise

## Scenario

Attacker modifies production build artifacts.

## Controls

- Protected branches
- Mandatory reviews
- Minimal CI permissions
- Short-lived cloud credentials
- Signed artifacts
- Reproducible builds where practical
- Dependency pinning
- SBOM
- Build provenance
- Release verification

---

# T29 — Dependency Compromise

## Scenario

A dependency update introduces malicious code.

## Controls

- Minimal dependency footprint
- Lockfiles
- Automated vulnerability scanning
- Dependency review
- Update policies
- High scrutiny for crypto and client dependencies
- Avoid unnecessary SDKs

---

# T30 — Malicious Software Update

## Scenario

An attacker distributes a fake desktop/browser/mobile update.

## Controls

- Signed releases
- Trusted stores
- Verified update channels
- Update signature validation
- Release transparency

---

# T31 — Denial of Service

## Scenario

Attackers consume:

- API capacity
- KDF resources
- database connections
- storage
- authentication capacity

## Controls

- Rate limiting
- Request limits
- Connection limits
- Queue limits
- Bounded workloads
- Abuse detection
- Infrastructure autoscaling where appropriate

---

# T32 — Resource Exhaustion Through KDF

## Scenario

Authentication or account creation endpoints trigger expensive Argon2 operations repeatedly.

## Controls

- Rate limits
- Client-side derivation where appropriate
- Bounded parameters
- Authentication throttling
- Resource isolation

---

# T33 — File Attachment Attack

## Scenario

Encrypted attachments are used to distribute malicious content.

The server may be unable to inspect encrypted contents.

## Controls

Must be addressed explicitly.

Potential strategies:

- Client-side warnings
- File size limits
- Restricted preview behavior
- Safe download handling
- Organization policies

Zero-knowledge architecture limits server-side malware inspection.

---

# T34 — Import File Attack

## Scenario

A malicious password-manager export exploits the importer.

## Controls

- Treat imports as untrusted input
- Strict parsing
- Input size limits
- Sandboxing where practical
- Fuzzing
- No dynamic code execution
- Secure temporary-file handling

---

# T35 — Export Leakage

## Scenario

A user exports an entire vault to plaintext.

## Controls

- Strong warnings
- Reauthentication
- Audit event
- Enterprise policy controls
- Safe temporary-file handling
- Explicit user action

An export is intentionally dangerous and must never happen silently.

---

# 7. Client-Specific Threats

## Web

Primary concerns:

- XSS
- malicious dependencies
- compromised origin
- browser extensions
- localStorage misuse
- service worker compromise

---

## Browser Extension

Primary concerns:

- message spoofing
- excessive host permissions
- malicious pages
- autofill attacks
- extension compromise
- phishing

---

## Desktop

Primary concerns:

- memory dumping
- local database theft
- update-channel compromise
- OS malware

---

## Mobile

Primary concerns:

- rooted/jailbroken devices
- insecure backups
- screenshot leakage
- malicious overlays
- weak biometric integration

---

# 8. Enterprise Threats

Enterprise functionality introduces additional risks:

```text
SSO compromise
SCIM abuse
Admin privilege escalation
Malicious recovery administrators
Group assignment errors
Domain takeover
Improper deprovisioning
SIEM data leakage
Policy bypass
```

Every enterprise capability must have an independent threat review before implementation.

---

# 9. Security Boundaries We Cannot Guarantee

The product cannot guarantee secrecy when:

### 1.

The client device is fully compromised while secrets are decrypted.

### 2.

An authorized user intentionally copies a secret.

### 3.

An authorized user had access to a secret before access was revoked.

### 4.

The user chooses an extremely weak master password and offline encrypted material is stolen.

### 5.

An endpoint or website receives a password legitimately through autofill and that endpoint itself is malicious or compromised.

These limitations must be documented honestly.

---

# 10. High-Risk Components

The following components require additional security review:

```text
Crypto Core
Recovery Protocol
Sharing Protocol
Browser Extension
Autofill Engine
Sync Protocol
Authentication
Organization Key Management
Import / Export
Update Mechanism
```

Changes to these components should require designated security review.

---

# 11. Security Testing Derived From This Threat Model

At minimum, automated testing must eventually cover:

- Cross-user access attempts
- Cross-organization access attempts
- Ciphertext modification
- Invalid cryptographic versions
- Replay attacks
- Stale revisions
- Invalid session tokens
- Expired sessions
- Revoked devices
- MFA bypass attempts
- Recovery misuse
- Malformed imports
- Oversized payloads
- Secret logging
- Unauthorized exports
- Permission escalation

---

# 12. Incident Priorities

## Critical

Examples:

- Vault plaintext disclosure
- Root key disclosure
- Master password disclosure
- Remote crypto bypass
- Authentication bypass leading to plaintext access
- Malicious release distribution

## High

Examples:

- Cross-account ciphertext access
- Organization authorization bypass
- Session compromise
- Recovery bypass
- Persistent XSS

## Medium

Examples:

- Sensitive metadata disclosure
- Limited audit bypass
- Missing security notifications

Severity depends on actual exploitability and impact.

---

# 13. Security Design Principle

The system should assume:

```text
Database may leak.
Backend may be compromised.
Infrastructure may be inspected.
Network may be hostile.
Users may lose devices.
Employees may make mistakes.
Dependencies may become malicious.
```

The architecture should ensure that any single failure has the smallest possible blast radius.

---

# 14. Threat Model Completion Criteria

This threat model is considered sufficient for starting cryptographic design when:

- Critical assets are identified
- Trust boundaries are defined
- Attacker capabilities are documented
- Database compromise is modeled
- Backend compromise is modeled
- Client compromise is modeled
- Recovery abuse is modeled
- Sharing abuse is modeled
- Organization threats are modeled
- Supply-chain threats are modeled
- Known security limitations are explicitly documented

---

# 15. Next Security Artifact

The next document must define:

```text
03_CRYPTOGRAPHIC_ARCHITECTURE.md
```

It must convert the threats identified here into a concrete key architecture covering:

- Master password
- Password-derived key
- Account root key
- Vault keys
- Item encryption
- Attachments
- Device keys
- Recovery keys
- Public/private user keys
- Organization keys
- Sharing
- Rotation
- Versioning
- Cryptographic serialization
