# Enterprise Password Manager

## Authentication and Session Protocol

**Status:** Draft v0.1
**Protocol Version:** 1
**Primary Authentication:** WebAuthn / Passkeys
**Vault Unlock:** Master Password + Account Secret
**Session Model:** Opaque Server-Managed Sessions

---

# 1. Objective

Define how a user:

- Creates an account
- Authenticates
- Establishes a session
- Unlocks the vault
- Reauthenticates
- Registers additional authenticators
- Revokes sessions
- Recovers access
- Signs out

without coupling server authentication with vault encryption.

---

# 2. Fundamental Separation

The system has two independent security states.

```text
SERVER AUTHENTICATION
```

answers:

> Who is this user?

Vault unlocking:

```text
VAULT UNLOCK
```

answers:

> Does this client possess the cryptographic material required to decrypt the user's vault?

These must remain separate.

---

# 3. V1 Authentication Decision

V1 authentication will be:

```text
Primary
    Passkey / WebAuthn

Vault Unlock
    Master Password
    +
    Account Secret
```

We will not introduce a second conventional account password in V1.

---

# 4. Why Passkeys

Passkeys provide public-key authentication.

The server stores a public credential.

The authenticator controls the private credential.

Conceptually:

```text
Authenticator
     │
     │ private key
     ▼

challenge
     ↓
signature
     ↓
Server
     ↓
public-key verification
```

No reusable password needs to be transmitted to or stored by the backend.

WebAuthn credentials are scoped to a Relying Party, which provides strong resistance against traditional credential phishing.

---

# 5. Authentication Does Not Unlock the Vault

Successful passkey authentication produces:

```text
Authenticated Session
```

not:

```text
ARK
```

Example state:

```text
Passkey authentication
        ↓
Server session
        ↓
AUTHENTICATED_LOCKED
```

Then separately:

```text
Master Password
+
Account Secret
        ↓
Argon2id
        ↓
MKEK
        ↓
ARK
        ↓
UNLOCKED
```

---

# 6. Client State Machine

```text
                 ┌────────────┐
                 │ SIGNED_OUT │
                 └─────┬──────┘
                       │
                 authenticate
                       │
                       ▼
          ┌─────────────────────────┐
          │ AUTHENTICATED_LOCKED    │
          └───────────┬─────────────┘
                      │
                  unlock vault
                      │
                      ▼
                ┌──────────┐
                │ UNLOCKED │
                └────┬─────┘
                     │
                     │ vault lock
                     ▼
          AUTHENTICATED_LOCKED
```

Server session expiry transitions the client toward:

```text
SIGNED_OUT
```

and should lock sensitive vault state.

---

# 7. Passkey Credential Model

Database entity:

```text
authenticators
```

Conceptually:

```text
id
user_id

credential_id
public_key

sign_count

transports
backup_eligible
backup_state

aaguid

created_at
last_used_at
revoked_at
```

No private authentication key exists server-side.

---

# 8. WebAuthn Registration

Account creation generates a server challenge.

```text
Client
   ↓
POST /auth/passkeys/registration/options
   ↓
Server generates challenge
   ↓
navigator.credentials.create()
   ↓
Authenticator creates credential
   ↓
Client sends attestation response
   ↓
Server verifies
   ↓
Public credential stored
```

---

# 9. Registration Challenge

Challenge requirements:

```text
CSPRNG generated
single use
short lifetime
purpose bound
user bound
origin bound by verification
RP bound by WebAuthn
```

Initial lifetime:

```text
5 minutes
```

Challenge state may live in Redis.

---

# 10. Challenge State

Example:

```text
challengeId
challenge
purpose
userId
createdAt
expiresAt
used
```

Possible purposes:

```text
REGISTER_PASSKEY
LOGIN
REAUTHENTICATE
ADD_PASSKEY
RECOVERY_ENROLLMENT
```

A challenge created for one purpose cannot be reused for another.

---

# 11. Challenge Replay

After successful verification:

```text
challenge → CONSUMED
```

Immediately.

Any second use returns failure.

Expired challenges are invalid.

---

# 12. WebAuthn RP Configuration

Production conceptually uses:

```text
RP ID:
    vault.example.com
or carefully selected parent RP domain

Allowed Origin:
    https://vault.example.com
```

The exact RP ID must be intentionally frozen before production because changing it later can invalidate credential usability.

---

# 13. User Verification

For the password manager:

```text
userVerification = required
```

where supported by the selected authentication flow.

The authenticator must perform local user verification such as:

- Device PIN
- Biometric
- Platform authentication mechanism

Biometric material itself is not sent to our server.

---

# 14. Discoverable Credentials

Preferred V1:

```text
residentKey = required
```

where supported.

This enables usernameless authentication:

```text
Open Vault
   ↓
Use passkey
   ↓
Authenticator selects account
```

instead of requiring:

```text
email
+
passkey
```

for every login.

---

# 15. Attestation

Consumer/default V1 policy:

```text
attestation = none
```

We do not need hardware identity information for ordinary users.

Future enterprise policy may optionally require approved authenticators or attestation.

That will be a separate policy feature.

---

# 16. Authentication Flow

Conceptually:

```text
GET/POST authentication options
        ↓
Server challenge
        ↓
navigator.credentials.get()
        ↓
Authenticator signs challenge
        ↓
Client sends assertion
        ↓
Server validates:
    challenge
    RP ID
    origin
    credential
    signature
    user verification
        ↓
Create session
```

---

# 17. Login Failure

Externally visible errors should remain generic.

Example:

```text
Authentication failed
```

Avoid providing unnecessary information that helps enumerate:

- Accounts
- Credentials
- Registered authentication methods

---

# 18. Credential Counter

WebAuthn signature counters may be recorded where available.

However:

> Session authentication must not rely exclusively on a monotonically increasing authenticator counter.

Synchronizable passkeys and authenticator implementations can have different counter behavior.

Suspicious counter changes may produce risk telemetry rather than automatic account destruction.

---

# 19. Multiple Passkeys

Users must be able to register multiple credentials.

Example:

```text
Daniel

├── MacBook Touch ID
├── iPhone Passkey
├── YubiKey Primary
└── YubiKey Backup
```

This reduces dependency on a single device.

---

# 20. Recommended Onboarding

During account creation:

```text
1. Verify email
2. Create first passkey
3. Configure Master Password
4. Generate Account Secret
5. Generate ARK/PVK
6. Generate Recovery Key
7. Create Recovery Kit
8. Confirm Recovery Kit possession
9. Create personal vault
```

---

# 21. Email Verification

Email establishes ownership of the communication address.

It does not:

```text
unlock ARK
```

and should not independently become equivalent to:

```text
full account recovery
```

---

# 22. Session Model

Use:

```text
opaque server-managed sessions
```

rather than long-lived authorization JWTs.

Session token:

```text
CSPRNG
    ↓
256-bit random token
```

Client receives the token.

Database stores only:

```text
SHA-256(sessionToken)
```

or another appropriate deterministic secure token lookup representation.

---

# 23. Why Opaque Sessions

Advantages:

```text
Immediate revocation

Simple device/session listing

Permission changes take effect immediately

No long-lived embedded roles

No JWT refresh-token hierarchy

Easy risk-state updates

Simple account-wide logout
```

---

# 24. Session Cookie

Preferred production cookie:

```text
__Host-pm_session=<random-token>
```

Attributes:

```text
Secure
HttpOnly
SameSite=Strict
Path=/
```

No:

```text
Domain=
```

OWASP recommends unpredictable server-side session identifiers and describes `Secure`, `HttpOnly`, `SameSite` and the `__Host-` prefix as important cookie/session protections.

---

# 25. Session Token Must Be Meaningless

The token must not encode:

```text
userId
email
role
organization
permissions
timestamp
```

It is purely a random identifier.

All session state resides server-side.

---

# 26. Session Record

Conceptually:

```text
Session {
    id
    userId
    deviceId?

    tokenHash

    status

    createdAt
    lastSeenAt

    idleExpiresAt
    absoluteExpiresAt

    authenticatedAt

    ipCreated
    lastIp

    authMethod
}
```

---

# 27. Session Expiration

We distinguish:

```text
idle timeout
```

from:

```text
absolute timeout
```

Initial V1 defaults can begin conservatively, for example:

```text
Idle authentication timeout:
    30 minutes

Absolute web session:
    12 hours
```

These are product defaults, not cryptographic requirements.

They must remain configurable later for enterprise policy.

---

# 28. Remember This Device

V1 may later offer:

```text
Remember this browser
```

which creates a longer-lived authentication session.

This is separate from:

```text
Remember vault unlock
```

V1 web should NOT persist ARK across browser restarts.

Therefore:

```text
browser remembered
+
server authenticated
```

can still result in:

```text
AUTHENTICATED_LOCKED
```

---

# 29. Vault Lock Timeout

Separate policy.

Example default:

```text
Vault auto-lock:
    5–15 minutes inactivity
```

Authentication session may continue after vault lock.

This allows:

```text
session valid
vault locked
```

without forcing full account login every few minutes.

---

# 30. Session Rotation

Generate a new session token after important authentication transitions.

Examples:

```text
initial authentication
reauthentication
recovery completion
major privilege change
```

Old token becomes invalid.

This helps mitigate session fixation.

---

# 31. Logout

```text
POST /api/v1/auth/logout
```

Server:

```text
hash current token
        ↓
find session
        ↓
mark REVOKED
        ↓
clear cookie
```

Client:

```text
lock vault
clear decrypted state
clear crypto references
clear sensitive local state
```

---

# 32. Logout All Devices

Sensitive operation:

```text
POST /api/v1/sessions/revoke-all
```

Requires recent reauthentication.

Effects:

```text
revoke every session
except optionally current session
```

or:

```text
revoke every session including current
```

depending on user action.

---

# 33. Session Revocation

Revoked sessions fail immediately.

No:

```text
wait until JWT expiration
```

is required.

This is an important reason for using server-managed sessions.

---

# 34. CSRF Model

Because authentication uses cookies, state-changing requests require explicit CSRF protection.

Defense layers:

```text
SameSite=Strict
+
Origin validation
+
CSRF token
```

`SameSite` is defense in depth, not the only protection.

---

# 35. CSRF Token

Use a synchronizer-style token.

Example:

```text
GET /api/v1/auth/csrf
```

returns a non-secret unpredictable CSRF token associated with the session.

Frontend sends:

```text
X-CSRF-Token: ...
```

for state-changing requests.

Server verifies:

```text
session
+
token
+
origin
```

---

# 36. Origin Validation

State-changing browser requests must originate from:

```text
https://vault.example.com
```

or another explicit allowlisted origin.

Do not use permissive wildcard CORS for authenticated APIs.

---

# 37. CORS

Production:

```text
Access-Control-Allow-Origin:
    exact trusted origin
```

Never:

```text
*
```

with credentialed endpoints.

Credentials:

```text
Access-Control-Allow-Credentials: true
```

only when architecture requires cross-origin API calls.

Same-origin deployment would simplify this considerably.

---

# 38. Preferred Deployment

Prefer:

```text
https://vault.example.com
```

with frontend and API operating under an architecture that minimizes cross-origin authentication complexity.

For example:

```text
vault.example.com/api/*
```

can reverse-proxy API traffic.

This simplifies:

- Cookies
- CSRF
- CORS
- CSP
- WebAuthn origin reasoning

---

# 39. Reauthentication

Some actions require recent proof of authentication even with an active session.

Examples:

```text
Add passkey
Remove passkey

Change recovery configuration

Generate new Recovery Kit

Delete account

Export vault

Register trusted device

Disable security controls

Revoke all sessions
```

OWASP recommends reauthentication for sensitive operations.

---

# 40. Reauthentication State

After successful passkey reauthentication:

```text
session.reauthenticatedAt = now
```

Sensitive endpoints can require:

```text
now - reauthenticatedAt <= 5 minutes
```

Initial example.

No special long-lived "sudo token" is necessary for V1.

---

# 41. Reauthentication Does Not Unlock Vault

Again:

```text
passkey reauthentication
```

proves identity to server.

It does not provide:

```text
ARK
```

If an operation also requires cryptographic key access, both conditions must hold.

Example:

```text
Generate Recovery Kit

requires:
    recent server reauthentication
    +
    unlocked vault
```

---

# 42. Sensitive Action Matrix

| Action                 | Session | Reauth | Vault Unlock |
| ---------------------- | ------: | -----: | -----------: |
| List encrypted items   |     Yes |     No |           No |
| View plaintext item    |     Yes |     No |          Yes |
| Create item            |     Yes |     No |          Yes |
| Change Master Password |     Yes |    Yes |          Yes |
| Add passkey            |     Yes |    Yes |           No |
| Remove passkey         |     Yes |    Yes |           No |
| Export vault           |     Yes |    Yes |          Yes |
| Rotate Recovery Key    |     Yes |    Yes |          Yes |
| Delete account         |     Yes |    Yes |          Yes |
| Revoke session         |     Yes |  Maybe |           No |
| Revoke all sessions    |     Yes |    Yes |           No |

---

# 43. Passkey Removal

Never allow removal of the final account recovery path without explicit protection.

Example policy:

A user may remove the final passkey only if another valid path exists, such as:

```text
another passkey
```

or a controlled recovery workflow.

The system should strongly encourage at least two authenticators.

---

# 44. Adding a Passkey

Requires:

```text
active session
+
recent authentication
```

Flow:

```text
Reauthenticate
      ↓
registration challenge
      ↓
new WebAuthn credential
      ↓
verify
      ↓
store public credential
      ↓
security audit event
      ↓
security notification
```

---

# 45. Passkey Removal Event

Removing an authenticator should produce:

```text
PASSKEY_REMOVED
```

audit event.

And security notification.

The removed credential must immediately stop authenticating.

---

# 46. Account Recovery Principle

There are two independent recovery problems:

```text
Identity Recovery
```

and:

```text
Vault Recovery
```

Both must succeed before a user can fully recover a lost account.

---

# 47. Recovery Scenario

User loses every passkey but has:

```text
email access
+
Recovery Kit
```

Recovery Kit contains:

```text
Account Secret
Recovery Key
```

This is sufficient to build a secure recovery flow without vendor access to ARK.

---

# 48. Recovery Start

Conceptual:

```text
POST /api/v1/recovery/start
```

User provides:

```text
email
```

Server sends a short-lived verification mechanism to the registered address.

Externally, response remains generic.

Example:

```text
If the account is eligible for recovery,
recovery instructions have been sent.
```

This reduces account enumeration.

---

# 49. Email Recovery Token

Recovery tokens must be:

```text
CSPRNG generated
single use
short lived
purpose bound
stored hashed server-side
```

Example lifetime:

```text
15 minutes
```

Email verification alone does not complete recovery.

---

# 50. Recovery Continuation

After email verification:

```text
LIMITED_RECOVERY_SESSION
```

is created.

It is not a normal authenticated session.

Allowed endpoints only:

```text
obtain recovery envelope
submit recovery transition
register replacement passkey
```

It cannot:

```text
download arbitrary vault data
manage account
export vault
```

until cryptographic recovery succeeds.

---

# 51. Cryptographic Recovery

Client obtains:

```text
Recovery ARK Envelope
```

Then locally:

```text
Recovery Key
+
Account Secret
       ↓
Recovery KEK
       ↓
ARK
```

Server never receives plaintext:

```text
Recovery Key
Account Secret
ARK
```

---

# 52. Recovery Completion

After ARK recovery:

```text
Generate new Master Password wrapping material

Generate new Recovery Key

Create new recovery envelope

Register new passkey
```

Then server atomically:

```text
replaces password/root envelope metadata
rotates recovery envelope
revokes existing sessions
revokes/flags old authentication credentials
increments security revision
writes audit events
```

---

# 53. Recovery Security Notification

After recovery:

notify using all available trusted channels.

Example:

```text
Account recovery completed
All existing sessions revoked
New authenticator registered
```

Do not include cryptographic secrets.

---

# 54. Lost Passkeys + Lost Recovery Kit

If user loses:

```text
all passkeys
+
Recovery Kit
```

we may still be able to prove identity through account processes, but:

```text
ARK cannot be recovered
```

under the zero-knowledge model.

The old vault becomes inaccessible.

A new empty account/vault may be created after sufficiently strong account ownership verification, depending on final policy.

---

# 55. Lost Master Password

If passkey remains available:

```text
authentication works
```

but vault stays locked.

Recovery requires:

```text
Recovery Kit
```

or another authorized cryptographic recovery mechanism.

Email alone cannot restore ARK.

---

# 56. MFA

Because passkey authentication with user verification is the primary V1 authenticator, we do not require a mandatory TOTP layer on top of every passkey login.

Future authentication options may include:

```text
TOTP
hardware security keys
enterprise identity providers
```

particularly where enterprise policies demand particular combinations.

---

# 57. TOTP

When introduced:

TOTP should primarily act as an additional authentication factor for weaker authentication paths.

It must never become:

```text
vault encryption key
```

or:

```text
recovery key
```

TOTP seed storage requires appropriate server-side protection because the server must normally verify generated codes.

---

# 58. Password Authentication Fallback

Conventional account-password authentication is intentionally deferred from V1.

Reason:

Adding:

```text
Account Password
+
Master Password
```

creates confusing UX and another reusable secret.

Using the same Master Password directly for traditional backend password authentication would weaken the separation we have intentionally designed.

---

# 59. OPAQUE

OPAQUE remains a future candidate for a password-based authentication fallback.

RFC 9807 describes OPAQUE as an augmented PAKE that can authenticate a client without revealing the password to the server, including during registration. However, RFC 9807 is an **Informational IRTF RFC**, not an Internet Standards Track specification.

Therefore V1 will not depend on OPAQUE.

---

# 60. Why Not Implement OPAQUE Immediately

Before adoption we would need:

```text
library maturity review
browser support strategy
native support strategy
cryptographic review
interoperability tests
recovery integration
formal protocol documentation
```

Passkeys already solve our primary server-authentication requirement with a mature web standard.

---

# 61. Authentication Rate Limits

Even public-key authentication endpoints require rate limits.

Apply limits to:

```text
registration
login challenge generation
recovery start
recovery verification
passkey registration
email verification
```

Rate limiting dimensions may include:

```text
IP
account
credential
device
global abuse signal
```

Avoid simplistic IP-only controls.

---

# 62. Credential Stuffing

Passkey-first architecture dramatically reduces conventional reused-password credential stuffing because normal login has no reusable account password.

It does not eliminate:

- session theft
- account recovery attacks
- malicious clients
- phishing around recovery
- compromised authenticators

---

# 63. Session Theft

If session cookie is stolen:

attacker may potentially:

```text
download encrypted vault state
access server metadata
perform actions permitted by session
```

but should still lack:

```text
ARK
```

unless the vault-unlock secret or client memory is also compromised.

---

# 64. Session Risk Events

Risk signals may include:

```text
new IP
new geography
unexpected user agent
session reuse anomalies
impossible travel
high request velocity
recovery activity
```

These signals must not become unreliable hard dependencies without careful tuning.

They may trigger:

```text
reauthentication
notification
session revocation
security review
```

---

# 65. IP Binding

Do not strictly bind a session to one IP.

Users legitimately move between:

```text
Wi-Fi
mobile networks
VPNs
corporate networks
```

IP changes may be risk signals, not automatic session invalidation.

---

# 66. User-Agent Binding

Likewise:

```text
User-Agent
```

is metadata, not a cryptographic authenticator.

It may support anomaly detection.

It must not determine identity.

---

# 67. Session Database Compromise

Database leak reveals:

```text
token hashes
session metadata
```

not plaintext bearer tokens.

Random 256-bit session tokens make practical inversion of properly generated token hashes infeasible.

---

# 68. Cookie Theft Through XSS

`HttpOnly` prevents ordinary JavaScript from directly reading the session cookie.

It does not make XSS harmless.

Malicious same-origin script could still make authenticated requests from the user's browser.

Therefore:

```text
CSP
Trusted Types where possible
minimal JS dependencies
no third-party vault scripts
```

remain essential.

---

# 69. Authentication Audit Events

At minimum:

```text
ACCOUNT_CREATED

EMAIL_VERIFIED

PASSKEY_ADDED
PASSKEY_REMOVED

LOGIN_SUCCESS
LOGIN_FAILURE

SESSION_CREATED
SESSION_REVOKED
ALL_SESSIONS_REVOKED

REAUTH_SUCCESS
REAUTH_FAILURE

RECOVERY_STARTED
RECOVERY_VERIFIED
RECOVERY_COMPLETED
RECOVERY_FAILED
```

---

# 70. Audit Privacy

Avoid recording unnecessary:

```text
WebAuthn challenge
credential response
email token
session token
CSRF token
```

Audit records contain identifiers and outcomes.

---

# 71. Email Security

Emails must never include:

```text
Master Password
Account Secret
Recovery Key
ARK
vault contents
```

Security emails may include:

```text
event
timestamp
approximate device information
account security URL
```

---

# 72. API Endpoint Draft

V1 authentication:

```text
POST /api/v1/accounts/start
POST /api/v1/accounts/verify-email

POST /api/v1/auth/passkeys/register/options
POST /api/v1/auth/passkeys/register/verify

POST /api/v1/auth/passkeys/login/options
POST /api/v1/auth/passkeys/login/verify

POST /api/v1/auth/reauth/options
POST /api/v1/auth/reauth/verify

POST /api/v1/auth/logout

GET    /api/v1/sessions
DELETE /api/v1/sessions/:id
POST   /api/v1/sessions/revoke-all

GET    /api/v1/auth/csrf

POST /api/v1/recovery/start
POST /api/v1/recovery/verify-email
POST /api/v1/recovery/complete
```

Exact contracts will be defined later.

---

# 73. Account Registration State

Accounts can move through:

```text
REGISTRATION_PENDING
        ↓
EMAIL_VERIFIED
        ↓
PASSKEY_REGISTERED
        ↓
CRYPTO_INITIALIZED
        ↓
ACTIVE
```

Incomplete registrations can expire automatically.

---

# 74. Registration Atomicity

The system must not leave an apparently usable account with:

```text
passkey
```

but no:

```text
valid root envelope
```

or vice versa.

Activation only occurs after all required onboarding components exist.

---

# 75. Authentication Transaction

After valid WebAuthn assertion:

```text
BEGIN

verify credential still active

create session

update authenticator last_used

write audit event

COMMIT
```

Only after success:

```text
Set-Cookie
```

is returned.

---

# 76. Recovery Transaction

Recovery completion must be atomic.

```text
BEGIN

verify limited recovery session

register replacement authenticator

replace root envelope

replace recovery envelope

invalidate old recovery mechanism

revoke existing sessions

increment security revision

write audit events

COMMIT
```

Partial recovery is unacceptable.

---

# 77. Account Security Page

The user should eventually see:

```text
Passkeys

Active Sessions

Known Devices

Recovery Kit Status

Recent Security Events
```

This becomes a core security UX feature, not merely settings decoration.

---

# 78. Passkey Metadata

Display only useful information:

```text
User-defined name
Created date
Last used date
Approximate authenticator type
```

Avoid fingerprinting or exposing excessive authenticator metadata.

---

# 79. Security Notifications

Notify on:

```text
new passkey
removed passkey
new session
recovery started
recovery completed
all sessions revoked
account deletion requested
```

Notification does not replace audit records.

---

# 80. Enterprise Extension

Later organizations may introduce:

```text
OIDC
SAML
enterprise passkey policy
hardware-key requirements
conditional access
managed-device requirements
```

These authenticate organization membership.

They still do not automatically reveal:

```text
ARK
```

---

# 81. SSO Principle

Future:

```text
Enterprise SSO
      ↓
Authenticated employee
```

must remain separate from:

```text
organization collection keys
personal ARK
```

SSO solves identity federation.

It does not solve zero-knowledge key distribution.

---

# 82. Authentication Invariants

### AUTH-001

Master Password is never sent to the backend for ordinary authentication.

### AUTH-002

Account Secret is never sent to the backend.

### AUTH-003

Authentication does not automatically unlock the vault.

### AUTH-004

V1 uses WebAuthn/passkeys as primary server authentication.

### AUTH-005

WebAuthn private keys remain in authenticators.

### AUTH-006

Session tokens are random opaque values.

### AUTH-007

Plaintext session tokens are never stored server-side.

### AUTH-008

Sessions are immediately revocable.

### AUTH-009

State-changing browser requests require CSRF protection.

### AUTH-010

Sensitive account operations require recent reauthentication.

### AUTH-011

Email access alone cannot decrypt or recover an existing vault.

### AUTH-012

Recovery requires user-controlled cryptographic material.

### AUTH-013

WebAuthn challenges are short-lived and single-use.

### AUTH-014

Removing a passkey is audited.

### AUTH-015

Recovery revokes or reevaluates pre-existing sessions.

---

# 83. V1 Authentication Scope

Implement:

```text
Email verification

Passkey registration

Passkey authentication

Opaque sessions

CSRF protection

Session listing

Session revocation

Passkey listing

Additional passkey registration

Passkey removal

Reauthentication

Recovery session

Recovery Kit-based recovery
```

Defer:

```text
Account password fallback
OPAQUE

TOTP
SMS

OIDC
SAML

Enterprise conditional access
Risk engine
Device attestation
```

---

# 84. Major Security Benefit

The intended compromise matrix becomes:

```text
Stolen session
    → server account access
    → vault remains encrypted if ARK unavailable

Database leak
    → ciphertext + public auth material
    → Account Secret unavailable

Email compromise
    → recovery initiation possible
    → Recovery Key still unavailable

Passkey compromise
    → authentication possible
    → Master Password + Account Secret still required to unlock new client

Master Password leak
    → Account Secret still required

Backend compromise
    → cannot directly decrypt stored vault
```

No single ordinary server-side compromise should provide the whole vault.

---

# 85. Next Artifact

Next:

```text
08_API_CONTRACT.md
```

We will translate the architecture into actual HTTP contracts covering:

```text
Registration
Authentication
Sessions
Crypto bootstrap
Vaults
Items
Sync
Recovery
Audit
```

For every endpoint we will specify:

```text
method
path
authentication
CSRF requirement
reauthentication requirement
request schema
response schema
errors
idempotency
audit behavior
```

After that:

```text
09_PRISMA_SCHEMA.md
```

and then:

```text
10_PROJECT_BOOTSTRAP.md
```

At that point implementation begins.
