# Auth Server — Technical Specification

## 1. Overview

Self-hosted, certification-ready authentication server built with NestJS. Designed to operate as a standalone auth service (like Firebase Auth / Supabase Auth) with Client SDK and Server SDK. Targets financial-grade security from Day 1 for future transaction approval, document signing, and payment authorization use cases.

**Goal:** Become the most comprehensively certified auth provider in the market. No existing provider holds all target certifications simultaneously.

---

## 2. Target Certifications

### 2.1 Certification Portfolio

| Certification | Type | Priority | Timeline | Estimated Cost (Audit) |
|---------------|------|----------|----------|----------------------|
| NIST SP 800-63B (AAL1-3) | Guideline | Day 1 design | - | Free |
| GDPR | Regulation | Day 1 design | Continuous | Ongoing |
| PSD2/PSD3 SCA | Regulation | Day 1 design | Continuous | Ongoing |
| OpenID Certified (Basic + FAPI 2.0) | Self-certification | Month 1-3 | 1-4 weeks | ~$2,500 |
| FIDO2 Server Certified | Automated test | Month 1-3 | 1-3 months | ~$5,000 + membership |
| SOC 2 Type II | CPA audit | Month 6-18 | 9-18 months | $30K-$150K |
| ISO 27001:2022 | Accredited CB | Month 6-18 | 6-18 months | $15K-$50K |
| HIPAA | BAA | Month 6-18 | With SOC 2 | Included |
| CSA STAR Level 2 | Certification | Month 12 | Post ISO 27001 | $10K-$30K |
| PCI DSS v4.0 | QSA audit | Month 12-18 | 3-12 months | $30K-$200K |
| FedRAMP (High) | US gov authorization | Month 18-24 | 12-18 months | $500K+ |
| eIDAS LoA High | EU regulation | Month 12-18 | 2-6 months | $10K-$100K |
| Common Criteria (EAL4) | CCTL evaluation | Month 24+ | 12-24 months | $150K-$500K |

### 2.2 Competitor Certification Comparison

| Provider | SOC 2 | ISO 27001 | HIPAA | PCI DSS | OpenID Cert | FIDO2 Cert | FedRAMP | CSA STAR |
|----------|-------|-----------|-------|---------|-------------|------------|---------|----------|
| Auth0 (Okta) | Yes | Yes | Yes | Yes | Yes + FAPI | No | No | Yes |
| Firebase (Google) | Yes | Yes | Yes | Yes* | Yes* | No | Yes* | - |
| Supabase | Yes | Pending | Yes | No | No | No | No | No |
| Clerk | Yes | - | Yes | - | No | - | No | No |
| Stytch | Yes | Yes | Yes | Partial | No | - | No | No |
| Descope | Yes | Yes | Yes | Yes | No | Yes | Yes (High) | Yes |
| Keycloak | N/A | N/A | N/A | N/A | Yes (most) | No | N/A | N/A |
| Hanko | - | - | - | - | No | Yes | No | No |
| FusionAuth | Yes | Yes | Yes | Partial | No | - | No | No |

*\* = inherited from Google Cloud*

**No single provider currently holds all target certifications.**

---

## 3. Core Architecture

### 3.1 Blocking Pipeline (Hook System)

The auth server uses a synchronous, blocking pipeline. The consuming backend MUST approve operations before they complete. This prevents race conditions where auth succeeds but the backend hasn't created its own user record yet.

```
Client SDK                Auth Server               App Backend
    |                         |                          |
    |--signIn(email,pass)--->|                          |
    |                         |--validate credentials-->|(internal)
    |                         |                          |
    |                         |--POST /hook ----------->|
    |                         |   {event, user, meta}    |
    |                         |   HMAC-SHA256 signed     |
    |                         |                          |
    |                         |<-- {allow: true/false} --|
    |                         |     HMAC-SHA256 signed   |
    |                         |                          |
    |<--token OR error-------|                          |
```

#### Hook Types

**Blocking hooks (before.\*)** — Pipeline stops, waits for backend response:

| Hook | Trigger | Use Case |
|------|---------|----------|
| `before.user.create` | Signup attempt | Backend creates own user, can deny |
| `before.login` | Every login | Ban check, business logic, custom validation |
| `before.otp.verify` | OTP verification | Custom fraud checks |
| `before.mfa.verify` | MFA verification | Device risk assessment |
| `before.password.reset` | Password reset request | Rate limiting, fraud prevention |
| `before.social.link` | Social account linking | Duplicate account prevention |
| `before.transaction.approve` | Financial transaction | Amount/payee verification |
| `before.token.refresh` | Token refresh | Session risk re-evaluation |

**Non-blocking hooks (after.\*)** — Fire-and-forget, informational:

| Hook | Trigger | Use Case |
|------|---------|----------|
| `after.user.create` | User created | CRM sync, welcome email |
| `after.login` | Login succeeded | Analytics, audit |
| `after.login.failed` | Login failed | Security monitoring |
| `after.password.change` | Password changed | Notification |
| `after.session.revoke` | Session revoked | Cleanup |

#### Hook Security

- Bidirectional HMAC-SHA256 signing: auth server signs outgoing hooks, backend signs responses
- Configurable timeout: 10-20 seconds (default: 15s)
- Configurable failure mode: `deny_on_failure` (secure default) or `allow_on_failure`
- Retry policy: configurable (0-3 retries with exponential backoff)
- Hook endpoints must be HTTPS only
- IP allowlisting for hook endpoints (optional)

### 3.2 Event System (Non-Blocking)

Separate from hooks. Events are emitted after operations complete. Used for analytics, monitoring, external integrations.

**Events emitted:**
- `user.created`, `user.updated`, `user.deleted`
- `auth.login.succeeded`, `auth.login.failed`, `auth.logout`
- `otp.generated`, `otp.verified`, `otp.failed`, `otp.expired`
- `mfa.enrolled`, `mfa.challenged`, `mfa.verified`, `mfa.failed`
- `session.created`, `session.refreshed`, `session.revoked`
- `token.issued`, `token.refreshed`, `token.revoked`
- `password.changed`, `password.reset.requested`, `password.reset.completed`
- `social.linked`, `social.unlinked`
- `device.registered`, `device.revoked`, `device.suspicious`
- `transaction.approve.requested`, `transaction.approve.completed`, `transaction.approve.denied`

**Delivery mechanisms:**
1. In-process EventEmitter (NestJS EventEmitter2)
2. Webhook delivery (Standard Webhooks Specification — webhook-id, webhook-timestamp, webhook-signature)
3. Pub/Sub (Redis Streams for horizontal scaling)

---

## 4. Authentication Flows

### 4.1 Email + Password

#### Register
1. Client: `auth.signUp({ email, password })`
2. Server validates password against policy (see 6.1)
3. Server checks email against compromised credential database
4. **`before.user.create` hook** → backend approves/denies
5. Server hashes password with Argon2id (peppered)
6. Server creates user record
7. Server sends verification email with signed token
8. Server issues session tokens (access JWT + opaque refresh)
9. Emits `user.created` event

#### Login
1. Client: `auth.signIn({ email, password })`
2. Server retrieves user by email (constant-time even if user doesn't exist — timing attack prevention)
3. Server verifies password hash (Argon2id, constant-time comparison)
4. If MFA enrolled → server returns `mfa_required` challenge
5. **`before.login` hook** → backend approves/denies
6. Server creates session, issues tokens
7. Emits `auth.login.succeeded` event

#### Password Reset
1. Client: `auth.resetPassword({ email })`
2. **`before.password.reset` hook** → backend approves/denies
3. Server generates cryptographically random reset token (256-bit)
4. Token stored hashed (SHA-256), expires in 1 hour
5. Server sends reset email
6. User clicks link → Client: `auth.confirmPasswordReset({ token, newPassword })`
7. Server validates token, checks new password against policy + last 4 passwords
8. Server re-hashes with Argon2id, invalidates all existing sessions
9. Emits `password.changed` event

#### Password Change (Authenticated)
1. Client: `auth.changePassword({ currentPassword, newPassword })`
2. Server verifies current password
3. Server validates new password against policy + last 4 passwords
4. Server re-hashes, optionally invalidates other sessions
5. Emits `password.changed` event

### 4.2 OTP (Email / SMS)

#### Request OTP
1. Client: `auth.signInWithOtp({ email })` or `auth.signInWithOtp({ phone })`
2. Server generates 6-digit TOTP (RFC 6238, 30-second window)
3. Server stores OTP hashed (SHA-256) with metadata: attempts=0, created_at, expires_at
4. Server sends OTP via email or SMS
5. Emits `otp.generated` event

#### Verify OTP
1. Client: `auth.verifyOtp({ email, code })`
2. Server checks rate limit (max 5 attempts per OTP, max 3 OTP requests per 15 minutes)
3. Server verifies OTP with constant-time comparison
4. **`before.otp.verify` hook** → backend approves/denies
5. Server creates session, issues tokens
6. Emits `otp.verified` event
7. OTP is immediately invalidated (single-use)

### 4.3 Social Login (OAuth2 / OIDC)

#### Web Flow (Authorization Code + PKCE)
1. Client SDK generates code_verifier (128-byte random) and code_challenge (SHA256)
2. Client SDK redirects to: `auth-server/oauth/{provider}/authorize?code_challenge=...&redirect_uri=...`
3. Auth server constructs provider-specific OAuth URL with PKCE + state parameter
4. Auth server redirects user to provider consent screen
5. Provider redirects back to auth server callback with authorization code
6. Auth server exchanges code + code_verifier with provider for access token
7. Auth server fetches user profile from provider
8. **`before.user.create` hook** (if new user) → backend approves/denies
9. **`before.login` hook** → backend approves/denies
10. Auth server creates/updates user, issues own tokens
11. Auth server redirects to client redirect_uri with session

#### Mobile Native Flow (Credential Exchange)
1. Mobile app uses native SDK (Google Sign-In, Apple Sign-In) to get provider token
2. Client SDK: `auth.signInWithCredential({ provider: 'google', idToken: '...' })`
3. Auth server verifies provider token directly with provider's API / JWKS
4. Same flow as web from step 7 onward

#### Backend-to-Backend Flow (Token Exchange)
1. Backend receives provider token from its own flow
2. Server SDK: `auth.admin.exchangeToken({ provider: 'google', accessToken: '...' })`
3. Auth server verifies token with provider
4. Auth server creates/updates user, returns admin-level session info

#### Supported Providers (initial)
- Google (OIDC)
- Apple (OIDC)
- GitHub (OAuth2)
- Microsoft / Azure AD (OIDC)
- Facebook (OAuth2)
- Custom OIDC (any provider with .well-known/openid-configuration)
- Custom OAuth2 (manual endpoint configuration)

### 4.4 WebAuthn / Passkeys (FIDO2)

#### Registration
1. Client: `auth.mfa.enroll('webauthn')` or `auth.passkey.register()`
2. Server generates challenge (16+ bytes, cryptographically random)
3. Server returns PublicKeyCredentialCreationOptions (rpId, rpName, user info, challenge, supported algorithms)
4. Client calls `navigator.credentials.create(options)`
5. Browser/platform creates key pair in Secure Enclave / TPM / TEE
6. Client sends attestation object to server
7. Server verifies: certificate chain, nonce, rpIdHash, signCount=0, aaguid, credentialId, public key
8. Server stores credential: public key, credential ID, sign count, attestation format
9. Server queries FIDO MDS v3 for authenticator metadata and status

#### Authentication
1. Server generates challenge, returns PublicKeyCredentialRequestOptions
2. Client calls `navigator.credentials.get(options)`
3. User verifies (biometric / PIN) on device
4. Client sends assertion (signature, authenticator data, client data)
5. Server verifies: signature with stored public key, challenge match, rpIdHash, sign count increment (clone detection)
6. If sign count regression detected → flag as potential cloned authenticator

### 4.5 Magic Link
1. Client: `auth.signInWithMagicLink({ email })`
2. Server generates signed token (Ed25519, 256-bit random, expires 15 minutes)
3. Server sends email with link containing token
4. User clicks link → Client: `auth.verifyMagicLink({ token })`
5. **`before.login` hook** → backend approves/denies
6. Server validates signature, expiry, single-use
7. Server creates session, issues tokens

### 4.6 Transaction Approval (PSD2 SCA Dynamic Linking)

1. Backend: `auth.admin.requestTransactionApproval({ userId, amount, payee, currency, metadata })`
2. Auth server creates transaction challenge: `challenge = server_nonce || amount || payee_id || timestamp`
3. Auth server sends push notification / in-app challenge to user's registered device
4. Client SDK displays transaction details to user (WYSIWYS — What You See Is What You Sign)
5. User confirms via biometric / PIN → device signs challenge with private key in TEE
6. Client: `auth.transaction.approve({ transactionId, deviceSignature })`
7. **`before.transaction.approve` hook** → backend final validation
8. Auth server verifies: device signature with stored public key, challenge binding to amount+payee, device attestation freshness
9. Auth server returns signed approval token containing transaction hash
10. Emits `transaction.approve.completed` event

**PSD2 RTS compliance:**
- Payer sees amount + payee during auth (WYSIWYS)
- Auth code is specific to amount + payee
- Any change to amount or payee invalidates auth code
- Max 5-minute lifetime for auth codes
- Max 5 failed attempts before lockout

---

## 5. Token Architecture

### 5.1 Access Token (JWT)

- **Format:** JWT (RFC 7519)
- **Signing:** Asymmetric — RS256 or EdDSA (Ed25519)
- **Lifetime:** 15 minutes (configurable, max 60 minutes)
- **Key rotation:** Every 90 days via JWKS endpoint
- **Claims:**

```json
{
  "iss": "https://auth.example.com",
  "sub": "user_xxxxxxxxxxxx",
  "aud": "https://api.example.com",
  "exp": 1700000900,
  "iat": 1700000000,
  "jti": "unique-token-id",
  "kid": "key-2026-01",
  "scope": "openid profile email",
  "tenant_id": "tenant_xxxx",
  "session_id": "sess_xxxx",
  "amr": ["pwd", "otp"],
  "acr": "urn:nist:800-63:aal2",
  "cnf": {
    "jkt": "dpop-thumbprint-if-dpop-bound"
  },
  "custom_claims": {}
}
```

### 5.2 Refresh Token (Opaque)

- **Format:** Opaque string (256-bit cryptographically random)
- **Storage:** Server-side (hashed with SHA-256)
- **Lifetime:** 30 days (configurable)
- **Rotation:** On every use — new refresh token issued, old one invalidated
- **Family-based revocation:** If a revoked refresh token is reused, the entire token family (all descendants) is revoked immediately — indicates token theft
- **Reuse detection window:** 10-second grace period for concurrent requests

### 5.3 DPoP (Demonstration of Proof-of-Possession)

Required for financial-grade operations. Optional for standard auth.

**DPoP Proof JWT:**
```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
}
{
  "htu": "https://auth.example.com/token",
  "htm": "POST",
  "jti": "unique-per-request",
  "iat": 1700000000
}
```

**Flow:**
1. Client generates ephemeral ES256 key pair
2. Client creates DPoP proof JWT signed with private key
3. Auth server validates proof, binds access token to public key via `cnf.jkt` claim
4. Every subsequent API request includes new DPoP proof + access token
5. Resource server validates: proof signature, `cnf.jkt` match, `jti` uniqueness, `iat` freshness

### 5.4 JWKS Endpoint

- `GET /.well-known/jwks.json`
- Always contains at least 2 keys during rotation (active + previous)
- Each key identified by `kid`
- Cache-Control headers control client refresh frequency
- **Rotation procedure (Zalando pattern):**
  1. Generate new key pair
  2. Publish new public key to JWKS (both old + new listed)
  3. Grace period (configurable, default 24 hours)
  4. New key becomes active signer
  5. Old key stops signing but remains in JWKS
  6. Remove old key after: retirement_time + max_token_lifetime + buffer

### 5.5 OpenID Connect Discovery

- `GET /.well-known/openid-configuration`
- Compliant with OpenID Connect Discovery 1.0
- Includes all required metadata: issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri, supported scopes, response types, grant types, signing algorithms

---

## 6. Security Requirements (All Certifications Combined)

### 6.1 Password Policy

| Requirement | Standard | Value |
|-------------|----------|-------|
| Minimum length | PCI DSS v4.0 (8.3.5) | 12 characters |
| Maximum length | NIST 800-63B | 64 characters (no truncation) |
| Complexity | PCI DSS v4.0 (8.3.5) | Numeric + alphabetic required |
| History | PCI DSS v4.0 (8.3.7) | Last 4 passwords cannot be reused |
| Compromised check | NIST 800-63B | Check against breached password database (HaveIBeenPwned k-anonymity API) |
| Hashing | NIST 800-63B, OWASP | Argon2id: m=64MB, t=3, p=1, ~300ms target |
| Salt | All standards | 16+ bytes, unique per password, cryptographically random |
| Pepper | SOC 2, best practice | HMAC-SHA256 applied before hashing, stored in HSM/KMS |
| Lockout threshold | PCI DSS v4.0 (8.3.4) | Max 10 failed attempts |
| Lockout duration | PCI DSS v4.0 (8.3.4) | Minimum 30 minutes |
| Constant-time comparison | NIST, timing attack prevention | `crypto.timingSafeEqual` for all credential checks |
| Rotation | PCI DSS v4.0 (8.3.6) | 90-day rotation OR dynamic risk-based analysis (v4.0 alternative) |

### 6.2 MFA Requirements

| Requirement | Standard | Value |
|-------------|----------|-------|
| Admin access | SOC 2, PCI DSS (8.4.1) | MFA mandatory |
| CDE access | PCI DSS (8.4.2) | MFA mandatory |
| Financial operations | PSD2 SCA | Two independent factors mandatory |
| TOTP | NIST AAL2 | RFC 6238, 6-digit, 30-second window, 1-step drift tolerance |
| WebAuthn/FIDO2 | NIST AAL3, FIDO2 cert | ES256 mandatory, packed + none attestation |
| SMS OTP | NIST 800-63B | Restricted authenticator — fallback only, user warned of risk |
| MFA bypass | PCI DSS (8.5.1) | Prohibited unless management-approved exception with time limit |
| Failed MFA attempts | PSD2 RTS | Max 5 before lockout |
| Replay prevention | PCI DSS, NIST | Each OTP/challenge single-use |
| Factor independence | PSD2 | Compromise of one factor must not compromise another |

### 6.3 Session Management

| Requirement | Standard | Value |
|-------------|----------|-------|
| Idle timeout (high security) | PCI DSS (8.2.8), NIST AAL3 | 15 minutes |
| Idle timeout (standard) | NIST AAL2 | 30 minutes |
| Absolute timeout | NIST 800-63B | 12 hours maximum |
| Auth code lifetime | PSD2 RTS | 5 minutes maximum |
| Session regeneration | OWASP | After privilege escalation (MFA completion, role change) |
| Concurrent sessions | SOC 2, best practice | Configurable limit per user |
| Session binding | NIST 800-63B | 64+ bits entropy for session secrets |
| TLS requirement | NIST 800-63B | All sessions over authenticated protected channels |

### 6.4 Encryption

| Requirement | Standard | Value |
|-------------|----------|-------|
| In transit | PCI DSS, SOC 2, ISO 27001 | TLS 1.2 minimum, TLS 1.3 preferred. SSLv3/TLS1.0/1.1 disabled |
| At rest | PCI DSS, SOC 2 | AES-256-GCM with envelope encryption (KEK + DEK) |
| Asymmetric keys | PCI DSS | RSA 2048+ or ECC 256+ |
| Key storage | SOC 2, PCI DSS | HSM or Cloud KMS (HSM-backed) |
| Key rotation | PCI DSS, SOC 2 | 90 days for JWT signing, annual for encryption keys |
| Split knowledge | PCI DSS (3.6.6) | Master key ceremony with dual control |
| Random generation | NIST | `crypto.randomBytes()` — 128-bit minimum for tokens, 256-bit for keys |

### 6.5 Rate Limiting & Anti-Abuse

| Control | Configuration |
|---------|---------------|
| Login attempts | 10/minute per IP, 5/minute per account |
| OTP requests | 3 per 15 minutes per account |
| OTP verification | 5 attempts per OTP code |
| Password reset | 3 per hour per account |
| Registration | 5 per hour per IP |
| Token refresh | 30/minute per session |
| API (general) | Configurable per endpoint, per tenant |
| Algorithm | Sliding window counter (Redis sorted sets, Lua script for atomicity) |

**Anti-abuse detection:**
- Impossible travel: Haversine distance / time > 500mph threshold → step-up auth
- Device fingerprint drift: Flag sessions where device characteristics change mid-session
- Credential stuffing: Detect high-volume distributed login attempts across accounts
- Bot detection: Challenge suspicious patterns (CAPTCHA integration point)

### 6.6 Device Attestation & Binding

#### Android (Google Play Integrity API)
- Standard request with `requestHash` for tamper protection
- Server decrypts verdict via Google API
- Required verdict for financial operations: `MEETS_DEVICE_INTEGRITY` or `MEETS_STRONG_INTEGRITY`
- `MEETS_VIRTUAL_INTEGRITY` (emulator) → deny financial operations
- Empty verdict (root/hook) → deny all sensitive operations

#### iOS (Apple App Attest)
- Secure Enclave generates ECDSA P-256 key pair
- 9-step server verification of attestation object
- Subsequent requests signed with Secure Enclave private key
- Sign counter validation for clone detection

#### Device Binding Flow
1. User authenticates (email + MFA)
2. Device generates key pair in hardware enclave (iOS Secure Enclave / Android Keystore with StrongBox)
3. Platform attestation proves key was generated in real hardware
4. Public key + device metadata stored on server, bound to user
5. Every subsequent sensitive request signed with device private key
6. Server verifies signature + device attestation status

### 6.7 Audit Logging

| Requirement | Standard | Implementation |
|-------------|----------|----------------|
| Coverage | SOC 2 (CC7.x), ISO 27001 (A.8.15) | All auth events logged |
| Format | SOC 2 auditor expectation | Structured JSON, UTC timestamps |
| Integrity | SOC 2 | Cryptographic hash chaining (SHA-256) — tamper-evident |
| Retention | SOC 2 | Minimum 1 year, 90 days searchable |
| Attribution | PCI DSS, SOC 2 | Every log entry tied to unique user ID |
| Alerting | SOC 2 (CC7.x), ISO 27001 (A.8.16) | Real-time alerts for brute force, impossible travel, credential stuffing, privilege escalation |
| PII masking | ISO 27001 (A.8.11), GDPR | Non-production environments use masked PII |
| Admin actions | PCI DSS, SOC 2 | Separate admin audit trail |
| Immutability | SOC 2 | Write-once storage or cryptographic chaining |

**Log entry structure:**
```json
{
  "event_id": "UUIDv7 (time-sortable)",
  "trace_id": "request correlation ID",
  "timestamp_utc": "ISO 8601",
  "event_type": "AUTH_LOGIN_SUCCESS",
  "actor": {
    "user_id": "pseudonymized if GDPR applies",
    "ip": "hashed or encrypted",
    "device_fingerprint": "hash",
    "user_agent": "truncated"
  },
  "target": {
    "resource": "session",
    "resource_id": "sess_xxxx"
  },
  "result": "success | failure",
  "risk_signals": {
    "impossible_travel": false,
    "new_device": true,
    "tor_exit": false
  },
  "prev_hash": "SHA-256 of previous log entry",
  "event_hash": "SHA-256(prev_hash + canonical(event_data))"
}
```

**GDPR Right to Erasure vs Audit Integrity — Solution:**

Cryptographic erasure: PII fields encrypted per-user with AES-256-GCM using per-user keys. On erasure request, delete the user's encryption key. Log chain stays intact but PII becomes permanently unreadable. GDPR Art. 17(3) also provides legal basis exception for "compliance with legal obligation."

### 6.8 GDPR Compliance

| Requirement | Article | Implementation |
|-------------|---------|----------------|
| Data minimization | Art. 5 | Collect only email + password hash. No unnecessary PII |
| Right to erasure | Art. 17 | User deletion endpoint + cryptographic erasure in logs |
| Data portability | Art. 20 | JSON export endpoint for all user data |
| Consent management | Art. 6/7 | Granular consent recording per purpose |
| Breach notification | Art. 33 | 72-hour notification to supervisory authority |
| DPIA | Art. 35 | Completed before deployment |
| Privacy by design | Art. 25 | Default settings = most privacy-protective |
| Pseudonymization | Art. 25 | Pseudonymized identifiers in logs |
| International transfers | Chapter V | Standard Contractual Clauses or adequacy decisions |

---

## 7. SDK Design

### 7.1 Client SDK (`@authserver/client`)

Platform: Web (Browser) + React Native + Flutter + iOS + Android

```typescript
// Initialization
const auth = createAuthClient({
  url: 'https://auth.example.com',
  apiKey: 'pk_live_xxxx',
  // Optional
  persistence: 'localStorage' | 'sessionStorage' | 'cookie' | 'memory',
  autoRefresh: true,
});

// --- Authentication ---
auth.signUp({ email, password })
auth.signIn({ email, password })
auth.signInWithOtp({ email })
auth.signInWithOtp({ phone })
auth.verifyOtp({ email, code })
auth.signInWithMagicLink({ email })
auth.verifyMagicLink({ token })
auth.signInWithOAuth({ provider: 'google', redirectTo: '...' })
auth.signInWithCredential({ provider: 'google', idToken: '...' })  // Mobile native
auth.signOut()
auth.signOut({ allDevices: true })

// --- Session ---
auth.getSession()
auth.getUser()
auth.getAccessToken()  // auto-refreshes if expired
auth.onAuthStateChange((event, session) => { ... })
// Events: 'SIGNED_IN', 'SIGNED_OUT', 'TOKEN_REFRESHED', 'USER_UPDATED', 'MFA_REQUIRED'

// --- Password ---
auth.resetPassword({ email })
auth.confirmPasswordReset({ token, newPassword })
auth.changePassword({ currentPassword, newPassword })

// --- MFA ---
auth.mfa.enroll({ type: 'totp' })       // Returns QR code URI
auth.mfa.enroll({ type: 'webauthn' })    // Triggers WebAuthn registration
auth.mfa.challenge({ type: 'totp' })
auth.mfa.verify({ type: 'totp', code: '123456' })
auth.mfa.verify({ type: 'webauthn' })    // Triggers WebAuthn assertion
auth.mfa.listFactors()
auth.mfa.unenroll({ factorId })

// --- Passkeys ---
auth.passkey.register()
auth.passkey.authenticate()
auth.passkey.list()
auth.passkey.revoke({ credentialId })

// --- Device ---
auth.device.register()           // Triggers platform attestation + key generation
auth.device.getAttestation()     // Returns current device attestation status
auth.device.listDevices()

// --- Transaction Approval (PSD2 SCA) ---
auth.transaction.approve({
  transactionId: 'txn_xxxx',
  amount: 150.00,
  currency: 'EUR',
  payee: 'Merchant Name',
})
// Triggers biometric/PIN → device signs challenge → returns approval

// --- User Profile ---
auth.updateUser({ displayName, avatar, metadata })
auth.deleteAccount()
auth.exportData()  // GDPR data portability
```

**Client SDK responsibilities:**
- PKCE code_verifier/challenge generation for OAuth flows
- Automatic token persistence (platform-appropriate storage)
- Automatic token refresh (background, before expiry)
- DPoP proof generation (when financial-grade mode enabled)
- Device attestation coordination
- Observable auth state for reactive frameworks

### 7.2 Server SDK (`@authserver/admin`)

Platform: Node.js (NestJS, Express, Fastify, etc.)

```typescript
// Initialization
const auth = createAuthAdmin({
  url: 'https://auth.example.com',
  serviceKey: 'sk_live_xxxx',
});

// --- Token Verification ---
auth.verifyToken(jwt)                          // Returns decoded payload or throws
auth.verifyToken(jwt, { audience: '...' })     // With audience check

// --- User Management ---
auth.admin.createUser({ email, password, metadata })
auth.admin.getUser(userId)
auth.admin.getUserByEmail(email)
auth.admin.updateUser(userId, { metadata, email, role })
auth.admin.deleteUser(userId)                  // Full GDPR erasure
auth.admin.listUsers({ page, limit, filter })
auth.admin.setCustomClaims(userId, { role: 'admin', tier: 'premium' })
auth.admin.banUser(userId, { reason, until })
auth.admin.unbanUser(userId)

// --- Session Management ---
auth.admin.listSessions(userId)
auth.admin.revokeSession(sessionId)
auth.admin.revokeAllSessions(userId)

// --- Custom Tokens ---
auth.admin.createCustomToken(userId, { claims, expiresIn })

// --- Blocking Hooks ---
auth.hooks.before('user.create', async (event) => {
  // event.user — user data being created
  // event.metadata — request metadata (IP, device, geo)
  // event.provider — auth provider used
  const myUser = await db.users.create({ authId: event.user.id, email: event.user.email });
  return { allow: true, metadata: { internalUserId: myUser.id } };
  // OR: return { allow: false, reason: 'Registration disabled' };
});

auth.hooks.before('login', async (event) => {
  const banned = await db.bans.check(event.user.id);
  if (banned) return { allow: false, reason: 'Account suspended' };
  return { allow: true };
});

auth.hooks.before('transaction.approve', async (event) => {
  const { amount, payee, currency, deviceSignature } = event;
  const withinLimits = await checkTransactionLimits(event.user.id, amount);
  return { allow: withinLimits };
});

// --- Non-Blocking Event Listeners ---
auth.on('user.created', async (event) => {
  await analytics.track('signup', event.user);
  await crm.createContact(event.user);
});

auth.on('login.failed', async (event) => {
  await securityMonitor.recordFailedLogin(event);
});

auth.on('transaction.approve.completed', async (event) => {
  await ledger.recordApproval(event);
});

// --- Device Management ---
auth.admin.listDevices(userId)
auth.admin.revokeDevice(userId, deviceId)
auth.admin.getDeviceAttestation(userId, deviceId)

// --- Tenant Management (Multi-tenancy) ---
const tenantAuth = auth.forTenant('tenant_xxxx');
tenantAuth.admin.createUser(...)  // Scoped to tenant
tenantAuth.admin.listUsers(...)   // Only returns tenant's users
```

### 7.3 SDK Design Principles

1. **Two distinct SDKs:** Client (untrusted, user-scoped) and Admin (trusted, full-access, service-key authenticated)
2. **Observable auth state:** `onAuthStateChange` for reactive UI frameworks
3. **Automatic token lifecycle:** Client SDK handles persistence, refresh, retry transparently
4. **Blocking hooks + non-blocking events:** Hooks control the pipeline, events inform
5. **Configuration-first:** Single init with URL + key. Multi-tenancy via scoped instances
6. **Type-safe:** Full TypeScript types, auto-generated from server OpenAPI spec
7. **Minimal dependencies:** Core SDK has zero runtime dependencies beyond platform APIs
8. **Tree-shakeable:** ESM modules, unused features don't increase bundle size

---

## 8. Key Management

### 8.1 Key Hierarchy

```
Root of Trust (HSM / Cloud KMS)
├── Master KEK (Key Encryption Key)
│   ├── JWT Signing Key (asymmetric, RS256 or EdDSA)
│   ├── Refresh Token Encryption Key (AES-256-GCM)
│   ├── Hook Signing Key (HMAC-SHA256)
│   ├── Audit Log Signing Key (Ed25519)
│   └── Per-User PII Encryption Keys (AES-256-GCM, envelope encrypted)
└── Pepper Key (HMAC-SHA256 for password hashing)
```

### 8.2 Key Storage

| Key | Storage | Rotation |
|-----|---------|----------|
| JWT signing (private) | HSM / Cloud KMS | 90 days |
| JWT signing (public) | JWKS endpoint | Follows private key rotation |
| Refresh token encryption | Cloud KMS (envelope) | Annually |
| Hook signing (HMAC) | Cloud KMS | 180 days |
| Audit log signing | HSM / Cloud KMS | Annually |
| Password pepper | HSM / Cloud KMS (never exported) | Annually (with rehash migration) |
| Per-user PII encryption | Database (DEK encrypted by KEK) | On KEK rotation, re-wrap DEKs |
| DPoP client keys | Client device (TEE/SE) | Ephemeral (per-session) |
| Device binding keys | Client device (TEE/SE) | Long-lived, revocable |

### 8.3 Key Ceremony (PCI DSS Compliant)

For master key generation:
1. Secure facility, no unauthorized electronics
2. Minimum 2 key custodians + 1 independent witness
3. HSM generates master key internally (never exposed as plaintext)
4. If split knowledge required: Shamir's Secret Sharing (3-of-5 quorum)
5. Shares distributed on tamper-evident smart cards
6. Each custodian stores share in separate physical safe
7. All actions logged, witnessed, video recorded
8. Post-ceremony: verify quorum reconstruction, destroy temporary materials
9. Documentation archived for compliance

---

## 9. Infrastructure Requirements

### 9.1 Database

- **Primary:** PostgreSQL 16+ (user data, sessions, credentials)
- **Cache/Rate limiting:** Redis 7+ (token blacklist, rate counters, distributed locks)
- **Audit logs:** Append-only store (PostgreSQL with write-only role, or dedicated log store)

### 9.2 External Integrations

| Integration | Purpose |
|-------------|---------|
| Cloud KMS (AWS KMS / GCP KMS / Azure Key Vault) | Key management, envelope encryption |
| SMTP / Email provider | OTP, magic link, verification emails |
| SMS provider (Twilio / equivalent) | SMS OTP (fallback) |
| HaveIBeenPwned API (k-anonymity) | Compromised password checking |
| Google Play Integrity API | Android device attestation |
| Apple App Attest | iOS device attestation |
| FIDO MDS v3 | WebAuthn authenticator metadata |
| OAuth providers (Google, Apple, GitHub, etc.) | Social login |
| Push notification service | Transaction approval challenges |

### 9.3 Deployment

- Container-based (Docker)
- Horizontally scalable (stateless auth server, shared Redis + PostgreSQL)
- Health check endpoints for orchestrator
- Graceful shutdown with connection draining
- Blue-green or canary deployment support

---

## 10. Multi-Tenancy

### 10.1 Isolation Model

Full tenant isolation (Firebase Identity Platform model):
- Each tenant has its own user pool
- Each tenant has its own provider configuration
- Each tenant has its own hook endpoints
- Each tenant has its own rate limit quotas
- JWT includes `tenant_id` claim

### 10.2 Tenant Configuration

```json
{
  "tenant_id": "tenant_xxxx",
  "name": "Acme Corp",
  "allowed_providers": ["email", "google", "apple"],
  "password_policy": { "min_length": 12, "require_mfa": true },
  "session_config": { "idle_timeout": 900, "absolute_timeout": 43200 },
  "hooks": {
    "before.user.create": "https://api.acme.com/auth/hooks/user-create",
    "before.login": "https://api.acme.com/auth/hooks/login"
  },
  "hook_signing_key": "whsec_xxxx",
  "branding": { "logo_url": "...", "primary_color": "#..." },
  "rate_limits": { "login": 10, "signup": 5 },
  "mfa_policy": "required | optional | disabled",
  "dpop_required": false,
  "device_attestation_required": false
}
```

---

## 11. OpenID Connect / OAuth 2.1 Compliance

### 11.1 Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /.well-known/openid-configuration` | Discovery |
| `GET /.well-known/jwks.json` | Public keys |
| `POST /oauth/authorize` | Authorization (with PAR support) |
| `POST /oauth/token` | Token exchange |
| `GET /oauth/userinfo` | User claims |
| `POST /oauth/revoke` | Token revocation |
| `POST /oauth/introspect` | Token introspection |
| `POST /oauth/par` | Pushed Authorization Request (FAPI) |
| `POST /oauth/device` | Device Authorization Grant |

### 11.2 Supported Grants

- Authorization Code + PKCE (mandatory for all clients)
- Refresh Token
- Client Credentials (service-to-service)
- Device Authorization (RFC 8628)
- Token Exchange (RFC 8693)

### 11.3 FAPI 2.0 Security Profile

When FAPI mode is enabled (per-tenant configurable):
- PAR required (authorization request sent server-to-server)
- PKCE required (S256 only)
- DPoP or mTLS required for sender-constrained tokens
- Response type: `code` only
- Short token lifetimes (5 minutes for auth codes, 5-15 minutes for access tokens)
- `s_hash` claim in ID token
- Request objects signed (JAR — JWT-Secured Authorization Request)

---

## 12. FIDO2 Server Certification Requirements

### 12.1 Conformance Tests

Must pass FIDO Alliance conformance test suite:
- WebAuthn API compliance (create + get ceremony)
- CBOR encoding/decoding
- Signature verification (ES256 mandatory, RS256 and EdDSA recommended)
- Challenge handling (16+ byte random, single-use)
- Origin validation (rpId matching)
- User presence (UP) and user verification (UV) flag checking
- Counter validation and clone detection

### 12.2 Attestation Formats

| Format | Requirement |
|--------|-------------|
| Packed | Mandatory — self-attestation + full attestation with x5c chain |
| None | Mandatory — privacy-preserving scenarios |
| fido-u2f | Recommended — backward compatibility |
| tpm | Recommended — Windows Hello |
| android-key | Recommended — Android biometrics |
| apple | Recommended — Apple platform authenticators |

### 12.3 Metadata Service

- FIDO MDS v3 integration for authenticator metadata
- Status monitoring for compromised authenticator models
- AAGUID-based policy enforcement (block/allow specific authenticator types)

---

## 13. PSD2/PSD3 SCA Compliance

### 13.1 Strong Customer Authentication

- Two of three factors: knowledge + possession + inherence
- Factors must be independent
- Dynamic linking for payment transactions (amount + payee bound to auth code)
- WYSIWYS (What You See Is What You Sign)
- Max 5-minute auth code lifetime
- Max 5 failed attempts
- Max 5-minute session inactivity timeout

### 13.2 Transaction Authorization Flow

See section 4.6.

### 13.3 Exemptions Engine

Configurable exemptions per PSD2 RTS:
- Low-value transactions (< EUR 30, cumulative limits)
- Recurring transactions (same amount + payee after initial SCA)
- Trusted beneficiaries (user-whitelisted)
- Transaction Risk Analysis (TRA) based on fraud rates
- Merchant-initiated transactions

---

## 14. NIST 800-63B Authentication Assurance Levels

### 14.1 AAL1 (Some Confidence)

- Single-factor authentication
- Password (min 8 chars, blocklist check) OR single-factor OTP
- Reauthentication: 30 min idle OR 12 hours absolute
- No MitM resistance required

### 14.2 AAL2 (High Confidence)

- Two different authentication factors
- Password + TOTP, or password + WebAuthn, or multi-factor crypto device
- SMS OTP allowed but restricted (user must be warned, alternative offered)
- Reauthentication: 30 min idle OR 12 hours absolute
- MitM resistance required
- Authentication intent required (physical action)

### 14.3 AAL3 (Very High Confidence)

- Two factors, at least one hardware cryptographic device
- WebAuthn hardware key + PIN/biometric, or hardware OTP + crypto device
- Reauthentication: 15 min idle OR 12 hours absolute
- MitM resistance required
- Verifier impersonation resistance required (rpId binding — WebAuthn provides this)
- Authentication intent required
- Software-only authenticators DO NOT qualify

---

## 15. Step-Up Authentication

### 15.1 Konsept

Kullanici giris yapmis durumda ama hassas bir islem icin ek dogrulama gerekiyor. Tam login degil, mevcut session uzerinde seviye yukseltme.

### 15.2 ACR/AMR Claims

- **ACR** (Authentication Context Class Reference): Token'daki guvenlik seviyesi. `aal1`, `aal2`, `aal3`
- **AMR** (Authentication Methods References): Kullanilan yontemler. `["pwd", "otp"]`, `["pwd", "hwk"]`
- Step-up sonrasi yeni token issued: daha yuksek ACR + guncel AMR

### 15.3 Per-Endpoint Zorunluluk

```
GET  /profile          -> AAL1 yeterli
POST /settings/email   -> AAL2 zorunlu (password degisikligi seviyesi)
POST /transfer         -> AAL2 + MFA zorunlu
POST /high-transfer    -> AAL3 + DPoP zorunlu (hardware key)
```

### 15.4 Step-Up Akisi

1. Client hassas endpoint'e istek atar
2. Server token'daki ACR'yi kontrol eder -> yetersiz
3. Server 403 doner: `{ "error": "step_up_required", "required_acr": "aal2", "challenge_id": "ch_xxx" }`
4. Client SDK step-up UI gosterir (TOTP veya passkey)
5. Kullanici dogrulama yapar
6. Server yeni token verir: `acr: "aal2"`, kisa omurlu (5-15dk)
7. Client orijinal istegi yeni token ile tekrar atar

### 15.5 Transaction-Specific Step-Up

PSD2 SCA icin: step-up challenge'a transaction detaylari (tutar + alici) embed edilir. Imza bu detaylara spesifik. Tutar/alici degisirse imza gecersiz.

---

## 16. Session Yonetimi (Detayli)

### 16.1 Session Lifecycle

```
Login basarili
  -> Session olusturulur (session_id, user_id, device_info, ip, created_at)
  -> Access token (JWT, 30dk) + Refresh token (opaque, rotation) verilir
  -> Idle timer baslar
  -> Absolute timer baslar
```

### 16.2 Device Metadata Binding

Her session'a baglanan bilgiler:
- IP adresi
- User-Agent
- Device fingerprint hash (screen, timezone, WebGL, canvas, audio context, hardware concurrency)
- Geo-location (ulke, sehir — IP-based)

Degisiklik tespit edildiginde:
- Minor (IP degisti ama ayni ulke): Log + devam
- Major (device fingerprint degisti): Step-up auth tetikle
- Critical (impossible travel): Session sonlandir + alert

### 16.3 Trusted Device Registry

- Kullanici "Bu cihazi hatirla" secerse → device token verilir
- Sonraki girislerde MFA atlanir (trusted device token gecerli ise)
- Device token: 256-bit random, SHA-256 hash saklanir, 30 gun gecerlilik
- Max 5 trusted device per kullanici
- Herhangi biri uzaktan revoke edilebilir

### 16.4 Concurrent Session Management

- Tenant yapilandirilabilir: max N session per kullanici
- Limit asildiginda strateji: `deny_new` veya `revoke_oldest`
- Kullanici tum aktif session'larini gorebilir (cihaz, konum, son aktivite)
- Tek tikla herhangi bir session'i kapatabilir

### 16.5 Session Anomaly Detection

| Anomali | Tespit | Aksiyon |
|---------|--------|---------|
| Impossible travel | Haversine mesafe / zaman > 500mph | Session sonlandir + alert |
| Device fingerprint drift | Ayni session'da cihaz ozellikleri degisti | Step-up auth |
| IP degisimi (farkli ulke) | GeoIP lookup | Step-up auth |
| Olagan disi saat | Kullanici profil pattern disinda | Risk score artir |
| Ani aktivite artisi | Kisa surede cok islem | Rate limit + alert |

---

## 17. Risk Engine (Detayli)

### 17.1 Sinyal Tablosu

| Sinyal | Kaynak | Agirlik | Hesaplama |
|--------|--------|---------|-----------|
| Device fingerprint degisimi | Client SDK | 0.4 | Onceki fingerprint ile Jaccard similarity |
| Impossible travel | IP geolocation | 0.5 | Haversine distance / time delta |
| IP reputation | IPinfo / MaxMind | 0.3 | VPN/Tor/proxy/hosting provider tespiti |
| Basarisiz login gecmisi | Auth DB | 0.2 | Son 1 saatteki basarisiz deneme sayisi |
| Bilinmeyen cihaz | Device registry | 0.2 | Kullanici icin ilk kez gorulme |
| Olagan disi saat | Kullanici profili | 0.1 | Normal login saatleri disinda |
| Request velocity | Rate limiter | 0.3 | Kisa surede cok fazla islem |
| Bot skoru | Bot detection | 0.4 | PoW challenge sonucu |
| Device attestation | Play Integrity / App Attest | 0.5 | Emulator / root / jailbreak tespiti |

### 17.2 Skor Hesaplama

```
risk_score = sum(signal_weight * signal_value) / sum(all_weights)
```

Sonuc: 0.0 (guvenli) - 1.0 (yuksek risk)

### 17.3 Risk-Based Aksiyonlar

| Risk Skoru | Aksiyon |
|------------|---------|
| 0.0 - 0.3 | Allow (normal akis) |
| 0.3 - 0.6 | Step-up auth (TOTP / email OTP) |
| 0.6 - 0.8 | Siki step-up (hardware key / biometric zorunlu) |
| 0.8 - 1.0 | Block + kullaniciya bildirim + admin alert |

Esik degerleri tenant bazinda yapilandirilabilir.

### 17.4 Pluggable Connectors

- Fingerprint.com (device intelligence)
- IPinfo / MaxMind (IP geolocation & reputation)
- Arkose Labs (bot detection)
- BreachSense / SpyCloud (credential monitoring)

Connector interface'i ile ucuncu parti servisler entegre edilebilir.

---

## 18. Bot Detection (Detayli)

### 18.1 Built-in: Proof-of-Work Challenge

- Self-hostable, privacy-preserving (ALTCHA modeli)
- Client cihazin CPU'su kriptografik puzzle cozer
- Insan dogrulama gerektirmez
- GDPR uyumlu (kullanici tracking yok)
- Zorluk seviyesi dinamik: risk skoru yukseldikce puzzle zorlasir
- Mobilde de calisir (lightweight puzzle)

### 18.2 Challenge Akisi

```
1. Client login formu gonderir
2. Server risk engine'den sinyal alir -> bot suphesi var
3. Server PoW challenge gonderir: { algorithm: "SHA-256", difficulty: 20, data: "random_prefix" }
4. Client SHA-256(data + nonce) hesaplar, ilk N bit'i 0 olan nonce bulana kadar dener
5. Client cozumu gonderir: { nonce: 12345 }
6. Server dogrular (tek hash hesabi, ucuz)
7. Gecerli ise login devam eder
```

### 18.3 Pluggable Entegrasyonlar

- Cloudflare Turnstile
- hCaptcha
- Arkose Labs
- GeeTest

### 18.4 Credential Stuffing Tespiti

- Cok sayida farkli hesaba ayni IP/fingerprint'ten login denemesi
- Dusuk basari orani + yuksek hacim = credential stuffing
- Otomatik IP/fingerprint bloklama
- Risk engine'e yuksek agirlikli sinyal

---

## 19. Account Recovery (Detayli)

### 19.1 Recovery Codes

- Kayit sirasinda 10 adet tek kullanimlik kod uretilir
- Her kod: 256-bit `crypto.randomBytes()`, base32 encoded (8 karakter gruplar)
- Argon2id ile hash'lenip saklanir
- Kullanici bunlari guvenli bir yere yazar
- Her kod tek kullanimlik — kullanildiktan sonra silinir
- Yeni kodlar uretildiginde eskiler gecersiz olur

### 19.2 Trusted Contacts (N-of-M)

- Kullanici 3-5 guvenilir kisi belirler
- Recovery icin M kisi onay vermeli (ornek: 2/3 veya 3/5)
- Her contact'a unique verification token gonderilir
- Contact onay verdiginde token auth server'a iletilir
- Yeterli onay toplandiktan sonra recovery baslar
- Google Recovery Contacts modeli

### 19.3 Recovery Passkey

- Ikinci cihaza kayitli yedek passkey
- `recovery: true` flag'i ile isaretlenir
- Sadece recovery islemlerinde kullanilabilir, normal login icin degil
- Kullanici bilgilendirilir: "Yedek cihazinizi guvenli tutun"

### 19.4 Admin-Assisted Recovery

- Admin panelinden identity verification sonrasi manual recovery
- Admin, kullanicinin kimligini harici yontemlerle dogrular (telefon, ID, vb.)
- Tam audit trail ile loglanir
- Yeni gecici sifre veya magic link gonderilir

### 19.5 Recovery Kurallari

- Recovery islemi ASLA MFA'yi bypass edemez (esdeger guvenlik seviyesi gerekli)
- Tum recovery islemleri audit log'a yazilir
- Recovery sonrasi tum mevcut session'lar sonlandirilir
- Recovery sonrasi yeni MFA enrollment zorunlu
- Recovery arasinda minimum bekleme suresi (brute force onleme)

---

## 20. Organization & Team Management (B2B Detayli)

### 20.1 Organization Yapisi

```
Organization
  |-- Settings (auth yontemleri, MFA politikasi, session timeout)
  |-- Members
  |     |-- Owner (tam yetki, tek kisi)
  |     |-- Admin (member yonetimi, konfigurasyon)
  |     |-- Member (standart erisim)
  |     |-- Custom roller (max 20 per org)
  |-- SSO Connections (SAML / OIDC per org)
  |-- API Keys (org-scoped)
  |-- Audit Logs (org-scoped)
  |-- SCIM Endpoint
```

### 20.2 Roller & Izinler

- Hiyerarsik: Owner > Admin > Member
- Custom roller: Izin koleksiyonlari. Ornek: `billing_admin` = `invoices.read` + `invoices.write` + `payment_methods.manage`
- Izinler string-based: `resource.action` formati
- Roller JWT custom claims'e eklenir: `{ "org_id": "org_xxx", "role": "admin", "permissions": [...] }`

### 20.3 Davet Sistemi

1. Admin davet gonderir (email + rol)
2. Davet token uretilir (256-bit, 7 gun gecerli)
3. Davet edilen kisi linke tiklar
4. Mevcut hesabi varsa → org'a eklenir
5. Hesabi yoksa → signup + org'a ekleme
6. Davet tek kullanimlik

### 20.4 Domain Verification

- Org admin `@acme.com` domain'ini dogrular (DNS TXT record veya email verification)
- Dogrulama sonrasi: `@acme.com` email'li tum yeni kullanicilar otomatik org'a eklenir
- Opsiyonel: Admin onayi zorunlu (auto-add vs approval-required)

### 20.5 Enterprise SSO per Org

- Her org kendi SAML IdP'sini veya OIDC provider'ini baglayabilir
- Self-service setup UI: SAML metadata upload veya OIDC discovery URL
- JIT (Just-in-Time) provisioning: IdP'den gelen kullanici otomatik olusturulur
- Per-org MFA politikasi: Org kendi MFA zorunlulugunu belirler

### 20.6 SCIM 2.0

- Per-org SCIM endpoint: `/scim/v2/Users`, `/scim/v2/Groups`
- Desteklenen islemler: Create, Read, Update, Delete, Search, Bulk
- Harici IdP (Okta, Azure AD) kullanici eklediginde/cikarttiginda otomatik sync
- SCIM bearer token per org

---

## 21. API Key, M2M & PAT (Detayli)

### 21.1 API Keys

- Kullanici veya organization-scoped
- Uzun omurlu opaque token
- Granular permission scope'lari: `read:users`, `write:users`, `admin:*`
- SHA-256 hash olarak saklanir (plaintext DB'de yok)
- Olusturma sirasinda tek seferlik gosterilir
- Revoke edilebilir, yeni key uretilir
- Rate limit per key (ayri konfigurasyon)
- Son kullanim tarihi + toplam request sayisi gorunur

### 21.2 M2M (Machine-to-Machine) Tokens

- OAuth 2.0 client_credentials flow
- Client ID + Client Secret → kisa omurlu JWT access token
- Organization-scoped: Token'da `org_id` claim'i
- Scope-based erisim kontrolu
- Kullanim: Microservice'ler arasi iletisim, cron job'lar, backend entegrasyonlar

### 21.3 Personal Access Tokens (PATs)

- Kullanici tarafindan olusturulan programmatic erisim token'lari
- GitHub PAT modeli
- Scope secimi: Kullanici hangi izinleri verecegini secer
- Sure limiti: Kullanici expiry belirler (max 1 yil)
- Revoke edilebilir
- Kullanicinin kendi yetkileri ile sinirli (escalation yok)

---

## 22. Admin Impersonation (Detayli)

### 22.1 Mekanizma

- RFC 8693 Token Exchange ile impersonation token uretilir
- Token claims:
  ```json
  {
    "sub": "usr_target",
    "act": { "sub": "admin_123" },
    "scope": "impersonation",
    "exp": "1 saat max"
  }
  ```
- `act` claim'i hangi admin'in impersonate ettigini belirtir

### 22.2 Audit Trail

- `admin.impersonate.start` event'i: admin_id, target_user_id, timestamp, reason
- Impersonation suresince yapilan TUM islemler `impersonated: true` flag'i ile loglanir
- `admin.impersonate.end` event'i: duration, actions_taken_count

### 22.3 Kurallar

- Sadece `impersonate` iznine sahip admin'ler yapabilir
- Max sure: tenant yapilandirilabilir (varsayilan 1 saat)
- Impersonate edilen kullaniciya bildirim gonderilir (tenant ayari)
- Impersonation sirasinda YASAKLI islemler:
  - Sifre degistirme
  - MFA ekleme/cikarme
  - Email degistirme
  - Hesap silme
  - Baska kullaniciyi impersonate etme

---

## 23. Webhook & Event Streaming (Detayli)

### 23.1 Webhook Subscription

- Tenant dashboard'dan veya API ile endpoint kaydi
- Event bazinda subscribe: Sadece ilgilendigi event'leri sec
- Fan-out: Ayni event birden fazla endpoint'e gonderilebilir
- Per-endpoint HMAC secret (otomatik uretilir)

### 23.2 Webhook Payload

```json
{
  "webhook_id": "wh_evt_xxxxx",
  "timestamp": "2026-03-30T12:00:00Z",
  "event_type": "user.created",
  "data": {
    "user_id": "usr_xxx",
    "email": "user@example.com",
    "auth_method": "email_password",
    "tenant_id": "tenant_xxx"
  }
}
```

Headers:
```
webhook-id: wh_evt_xxxxx
webhook-timestamp: 1711800000
webhook-signature: v1,HMAC-SHA256(secret, webhook_id.webhook_timestamp.body)
```

### 23.3 Retry Politikasi

| Deneme | Bekleme | Toplam |
|--------|---------|--------|
| 1 | Aninda | 0 |
| 2 | 1 dakika | 1dk |
| 3 | 5 dakika | 6dk |
| 4 | 30 dakika | 36dk |
| 5 | 2 saat | 2sa 36dk |
| 6 (son) | 24 saat | ~26sa |

- 2xx → basarili, retry yok
- 4xx → Dead Letter Queue, retry yok (client hatasi)
- 5xx / timeout → retry

### 23.4 Dead Letter Queue (DLQ)

- Tum retry'lar basarisiz → DLQ'ya gider
- Dashboard'dan goruntulenebilir: event, endpoint, hata, deneme sayisi
- Manuel "Retry" butonu
- Toplu replay secenegi
- DLQ retention: 30 gun

### 23.5 Event Replay

- Belirli bir timestamp'ten itibaren tum event'leri tekrar gonderme
- Endpoint degisikligi sonrasi veya downtime recovery icin
- Rate limited: Max 100 event/saniye replay hizi

---

## 24. Breach Detection (Detayli)

### 24.1 HaveIBeenPwned k-Anonymity

- Kayit ve sifre degisikliginde otomatik kontrol
- Sifrenin SHA-1 hash'inin ilk 5 karakteri gonderilir
- HIBP eslesen tum hash'leri doner
- Server kendi tarafinda tam eslemeyi kontrol eder
- Sifre ASLA HIBP'ye gonderilmez
- NIST 800-63B bunu zorunlu kiliyor

### 24.2 Credential Monitoring

- Pluggable dark web monitoring: BreachSense, SpyCloud, Enzoic
- Periyodik kontrol: Kullanici email'leri yeni breach'lerde var mi?
- Etkilenen kullanicilar icin:
  - Zorunlu sifre degisikligi
  - Tum session'lar sonlandirilir
  - Kullaniciya bildirim email'i
  - Admin'e alert

### 24.3 Credential Stuffing Tespiti

- Pattern: Cok sayida farkli hesaba ayni IP/fingerprint'ten login denemesi
- Dusuk basari orani (<%5) + yuksek hacim (>100/saat) = credential stuffing
- Otomatik IP/fingerprint bloklama
- Risk engine'e yuksek agirlikli sinyal olarak iletilir

---

## 25. Compliance Automation (Detayli)

### 25.1 GDPR Data Subject Request Endpoints

```
GET    /admin/users/:id/export     → Kullanici verisini JSON olarak export
DELETE /admin/users/:id            → Kullanici verisi sil + log'larda cryptographic erasure
GET    /admin/users/:id/consents   → Consent gecmisi
POST   /admin/users/:id/consents   → Consent kaydi (purpose, timestamp, version)
PUT    /admin/users/:id/consents/:id/revoke → Consent geri cekme
```

### 25.2 Data Retention Otomasyonu

- Tenant bazinda yapilandirilabilir retention suresi
- Suresi dolan veriler otomatik temizlenir (per-user encryption key silme ile)
- Retention politikasi degisiklikleri audit log'a yazilir

### 25.3 Compliance Raporlari

- Login basari/basarisizlik istatistikleri (trend)
- MFA adoption orani (MFA aktif kullanici yuzdesi)
- Password age dagilimi (kac kullanicinin sifresi 90 gunden eski)
- Session anomali raporlari
- Audit log export (JSON/CSV, compliance-friendly format)
- DSAR request gecmisi

---

## 26. AI Agent & MCP Auth (Detayli)

### 26.1 Agent Entity Tipi

Kullanici ve service account'larin yaninda ucuncu entity tipi: **agent**

```json
{
  "entity_type": "agent",
  "agent_id": "agent_xxx",
  "name": "My AI Assistant",
  "owner_id": "usr_xxx",
  "scopes": ["read:profile", "write:tasks"],
  "max_delegation_level": 1
}
```

### 26.2 OAuth 2.1 Client Credentials

- Agent OAuth 2.1 client credentials ile kendini dogrular
- Client ID + Client Secret → kisa omurlu JWT
- Token'da `entity_type: "agent"` claim'i

### 26.3 Token Exchange (RFC 8693) — Delegation

Kullanici "bu agent benim adima su islemleri yapabilir" diyor:

```
POST /oauth/token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<user_access_token>
subject_token_type=urn:ietf:params:oauth:token-type:access_token
requested_token_type=urn:ietf:params:oauth:token-type:access_token
actor_token=<agent_client_credentials_token>
scope=read:profile write:tasks
```

Response token claims:
```json
{
  "sub": "usr_xxx",
  "act": { "sub": "agent_xxx" },
  "scope": "read:profile write:tasks",
  "may_act": { "sub": "agent_xxx", "max_scope": "read:profile write:tasks" }
}
```

### 26.4 MCP Server Uyumu

- OAuth 2.1 + PKCE zorunlu (MCP spec)
- Dynamic client registration destegi
- Agent identity ve kullanici identity ayristirmasi

---

## 27. Decentralized Identity / EUDI Wallet (Detayli)

### 27.1 Neden Onemli (2026-2027)

- eIDAS 2.0: 2026 sonuna kadar tum AB uye devletleri EUDI Wallet sunmali
- 2027'den itibaren bankacilik, telekom, saglik sektorleri EUDI Wallet'i KABUL ETMEK ZORUNDA
- Teknik stack: W3C Verifiable Credentials + OpenID for Verifiable Credentials (OID4VCI/OID4VP) + SD-JWT VC

### 27.2 Auth Server Rolu: Verifier

Auth server VC Verifier olarak calisir:

```
1. Kullanici EUDI Wallet'i acar
2. Auth server OpenID4VP (Verifiable Presentations) isteği gonderir
3. Wallet kullaniciya hangi bilgilerin paylasilacagini gosterir
4. Kullanici onaylar → Wallet imzali VP (Verifiable Presentation) gonderir
5. Auth server VP'yi dogrular: imza, issuer, gecerlilik, revocation check
6. Auth server credential'lardaki bilgilerle kullanici olusturur/dogrular
```

### 27.3 Selective Disclosure

- SD-JWT VC formati ile sadece gereken bilgiler paylasilir
- Ornek: "18 yasindan buyuk musun?" → "Evet" (dogum tarihi paylasilmaz)
- Ornek: "Ad-soyad" → paylasilir, "Adres" → paylasilmaz
- Privacy-preserving: Minimum veri ilkesi (GDPR uyumlu)

---

## 28. Edge SDK (Detayli)

### 28.1 Amac

Cloudflare Workers, Vercel Edge, Deno Deploy gibi edge runtime'larda JWT dogrulama. Auth server'a network round-trip yapmadan.

### 28.2 API

```typescript
import { createVerifier } from '@authserver/edge';

const verifier = createVerifier({
  jwksUrl: 'https://auth.example.com/.well-known/jwks.json',
  issuer: 'https://auth.example.com',
  audience: 'my-app',
  jwksCacheTtl: 3600, // 1 saat cache
});

// JWT dogrulama
const { valid, claims, error } = await verifier.verify(token);

// DPoP dogrulama (opsiyonel)
const dpopValid = await verifier.verifyDPoP(dpopProof, token, {
  method: 'POST',
  url: 'https://api.example.com/transfer'
});

// ACR seviyesi kontrolu
const meetsRequirement = verifier.checkAcr(claims, 'aal2');
```

### 28.3 Teknik Gereksinimler

- <50KB bundle size (edge runtime memory kisitlamalari)
- Sifir runtime dependency
- JWKS response caching (configurable TTL)
- `kid` bazli key secimi
- RS256, EdDSA, ES256 algoritmalarini destekler
- Web Crypto API kullanir (Node.js crypto degil)

---

## 29. Database Semasi

### 29.1 Core Tablolar

```
tenants
  id, name, slug, config (JSONB), created_at, updated_at

users (tenant-scoped)
  id, tenant_id, email_encrypted, email_hash (for lookup), phone_encrypted,
  display_name_encrypted, avatar_url, email_verified, phone_verified,
  banned, ban_reason, metadata (JSONB), created_at, updated_at

identities (user has many)
  id, user_id, provider (email, google, apple, github, webauthn),
  provider_user_id, provider_data (JSONB), created_at

credentials
  id, user_id, type (password, totp),
  credential_data_encrypted (hash for password, secret for TOTP),
  password_history (last 4 hashes), created_at, updated_at

sessions
  id, user_id, tenant_id, device_id, ip, user_agent, device_fingerprint_hash,
  geo_country, geo_city, acr, amr (JSONB), idle_timeout_at, absolute_timeout_at,
  created_at, last_activity_at, revoked_at

refresh_tokens
  id, session_id, user_id, token_hash (SHA-256), family_id,
  parent_id (for rotation chain), used, created_at, expires_at

devices
  id, user_id, public_key, attestation_type, attestation_data (JSONB),
  platform (ios, android, web), device_name, sign_count,
  trusted, trusted_until, created_at, last_used_at

mfa_enrollments
  id, user_id, type (totp, webauthn, sms, email),
  secret_encrypted (for TOTP), credential_id (for webauthn),
  phone_encrypted (for SMS), verified, created_at

webauthn_credentials
  id, user_id, credential_id_b64, public_key_cbor, sign_count,
  attestation_format, aaguid, transports (JSONB),
  is_passkey, is_recovery, created_at, last_used_at

recovery_codes
  id, user_id, code_hash (Argon2id), used, created_at, used_at

organizations
  id, tenant_id, name, slug, domain, domain_verified,
  settings (JSONB), created_at

org_members
  id, org_id, user_id, role, custom_permissions (JSONB),
  invited_by, joined_at

org_sso_connections
  id, org_id, type (saml, oidc), config (JSONB),
  metadata_url, enabled, created_at

api_keys
  id, tenant_id, org_id (nullable), user_id (nullable),
  key_hash (SHA-256), key_prefix (first 8 chars for identification),
  scopes (JSONB), name, last_used_at, expires_at, revoked_at

oauth_clients
  id, tenant_id, client_id, client_secret_hash,
  redirect_uris (JSONB), grant_types (JSONB),
  scopes (JSONB), client_type (public, confidential), created_at

audit_logs (append-only)
  id (UUIDv7), tenant_id, event_type, actor_encrypted, target,
  result, metadata_encrypted, risk_score,
  prev_hash, event_hash, created_at

webhook_subscriptions
  id, tenant_id, url, events (JSONB), secret_hash,
  enabled, created_at

webhook_deliveries
  id, subscription_id, event_id, status (pending, success, failed, dlq),
  attempts, last_attempt_at, next_retry_at,
  request_body, response_status, response_body, created_at

hook_configs
  id, tenant_id, event (before.user.create, before.login, ...),
  url, signing_key_hash, timeout_ms, failure_mode,
  enabled, created_at

user_consents
  id, user_id, purpose, granted, version, ip, user_agent,
  granted_at, revoked_at
```

### 29.2 Sifreleme Stratejisi

| Alan | Yontem | Key |
|------|--------|-----|
| PII (email, telefon, isim) | AES-256-GCM | Per-tenant DEK (KEK ile sifreli) |
| Credentials (TOTP secret) | AES-256-GCM | Per-user DEK |
| Audit log PII | AES-256-GCM | Per-user DEK (cryptographic erasure icin) |
| Password hash | Argon2id (one-way) | Pepper (HMAC) + salt |
| Token hash'leri | SHA-256 (one-way) | Salt yok (random token zaten unique) |
| API key hash | SHA-256 (one-way) | Salt yok |

### 29.3 Index Stratejisi

- `users.email_hash` — deterministic hash ile email lookup (sifreli alanda arama yapabilmek icin)
- `sessions.user_id` + `sessions.revoked_at IS NULL` — aktif session'lar
- `refresh_tokens.token_hash` — token lookup
- `audit_logs.tenant_id` + `audit_logs.created_at` — tenant bazinda log sorgulama
- `audit_logs.event_type` + `audit_logs.created_at` — event tipi bazinda filtreleme
- Tum tablolarda `tenant_id` uzerinde index (multi-tenant query isolation)

---

## 30. PSD3 Hazirlik

### 30.1 Durum (Mart 2026)

- Kasim 2025: AB Parlamento ve Konsey arasinda gecici politik anlasma
- 2026 ortasi: Resmi yayin bekleniyor
- 2027 sonu: Zorunlu uyum bekleniyor (18-21 ay gecis suresi)

### 30.2 PSD3 Yeni Gereksinimleri

| Gereksinim | PSD2'den Farki | Bizim Hazirligimiz |
|------------|----------------|-------------------|
| Guclendirilmis SCA | Daha siki kurallar | Faz 3'te PSD2 SCA zaten implemente |
| Gercek zamanli fraud monitoring | Yeni zorunluluk | Risk engine (Faz 2) + breach detection (Faz 4) |
| API hardening | Daha siki standartlar | FAPI 2.0 (Faz 3) zaten karsilar |
| eIDAS 2.0 uyumu | EUDI Wallet entegrasyonu | Faz 5'te EUDI Wallet destegi |
| Daha genis compliance kapsami | Delegated entitlements | Multi-tenant izolasyon (Faz 0'dan itibaren) |
| Daha siki fraud sorumluluk | PSP sorumlulugu artiyor | Audit log + risk engine kanit saglar |

---

## 31. Rakip Analizi (Detayli)

### 31.1 Sertifika Karsilastirmasi

| Ozellik | Biz (Hedef) | Auth0 | Firebase | Supabase | Descope | Hanko | Clerk |
|---------|-------------|-------|----------|----------|---------|-------|-------|
| OpenID FAPI 2.0 | Hedef | FAPI 1 | Hayir | Hayir | Hayir | Hayir | Hayir |
| FIDO2 Certified | Hedef | Hayir | Hayir | Hayir | Evet | Evet | Hayir |
| SOC 2 Type II | Hedef | Evet | Evet | Evet | Evet | Hayir | Evet |
| ISO 27001 | Hedef | Evet | Evet | Beklemede | Evet | Hayir | Hayir |
| PCI DSS v4.0 | Hedef | Evet | Evet | Hayir | Evet | Hayir | Hayir |
| FedRAMP High | Hedef | Hayir | Evet* | Hayir | Evet | Hayir | Hayir |
| HIPAA | Hedef | Evet | Evet | Evet | Evet | Hayir | Evet |
| CSA STAR | Hedef | Evet | Hayir | Hayir | Evet | Hayir | Hayir |
| eIDAS | Hedef | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir |
| PSD2/PSD3 SCA | Hedef | Evet | Hayir | Hayir | Hayir | Hayir | Hayir |

### 31.2 Ozellik Karsilastirmasi

| Ozellik | Biz (Hedef) | Auth0 | Firebase | Supabase | Descope | Clerk |
|---------|-------------|-------|----------|----------|---------|-------|
| Blocking Hooks | Evet | Evet | Hayir | Kismi | Hayir | Hayir |
| Device Attestation | Evet | Hayir | Hayir | Hayir | Hayir | Hayir |
| Transaction Approval | Evet | Hayir | Hayir | Hayir | Hayir | Hayir |
| Self-hosted | Evet | Hayir | Hayir | Evet | Hayir | Hayir |
| AI Agent Auth | Evet | Evet | Hayir | Hayir | Hayir | Hayir |
| EUDI Wallet | Evet | Hayir | Hayir | Hayir | Hayir | Hayir |
| Risk Engine | Evet | Evet | Hayir | Hayir | Evet | Hayir |
| Edge SDK | Evet | Hayir | Hayir | Hayir | Hayir | Evet |
| Tamper-Evident Logs | Evet | Hayir | Hayir | Hayir | Hayir | Hayir |

---

## 32. Email Altyapisi & Guvenligi

### 32.1 Anti-Spoofing (PCI DSS v4.0 zorunlu)

- **SPF**: DNS'te hangi sunucularin email gonderebilecegi tanimlanir
- **DKIM**: Her email kriptografik olarak imzalanir
- **DMARC**: `p=reject` ile sahte emailler reddedilir

### 32.2 Email Gonderim

- Pluggable provider: AWS SES, SendGrid, Postmark, SMTP
- Tenant bazinda email konfigurasyonu (kendi SMTP'sini kullanabilir)
- Bounce handling: Hard bounce → email'i unverified yap. Soft bounce → retry
- Complaint handling: Spam sikayet → log + tenant'a bildir
- Rate limit: Kullanici basina saatte max email sayisi
- Template rendering'de XSS koruması (sandboxed, otomatik escape)
- Plaintext fallback her email icin zorunlu

---

## 33. SAML 2.0

### 33.1 SP (Service Provider) Modu

Auth server SAML SP olarak calisir — harici SAML IdP'lerden identity kabul eder.

- SAML Assertion parsing ve dogrulama
- XML Signature Verification (XML DSig)
- Assertion encryption destegi (AES-256)
- NameID format destegi: emailAddress, persistent, transient
- Single Logout (SLO) destegi
- Metadata endpoint: `/.well-known/saml-metadata.xml`

### 33.2 IdP (Identity Provider) Modu

Auth server kendisi SAML IdP olarak calisir.

- SAML Response/Assertion uretimi
- SP metadata import
- Attribute mapping (SAML attributes → user claims)
- Per-tenant IdP konfigurasyonu

### 33.3 Guvenlik

- XXE koruması: External entity resolution KAPALI
- DTD processing KAPALI
- XML bomb (billion laughs) koruması: max entity depth + max document size

---

## 34. HTTP & Transport Guvenligi

### 34.1 Security Headers

Tum response'larda:
```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 0
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cache-Control: no-store, no-cache, must-revalidate (auth endpoint'lerinde)
```

### 34.2 CORS

- Tenant bazinda origin whitelist
- Wildcard (`*`) origin YASAK
- Credentials mode'da sadece explicit origin'ler
- Preflight cache: max 1 saat

### 34.3 IP Allowlisting

- Admin API'leri icin IP allowlist (tenant yapilandirilabilir)
- Management API icin ayri allowlist
- IPv4 ve IPv6 CIDR destegi

### 34.4 Request Validation

- Max request body size: 1MB
- Content-Type validation: Sadece `application/json`
- JSON depth limit: Max 10 seviye
- Input sanitization: Tum string input'lar trim + length check

---

## 35. Data Residency & Sovereignty

### 35.1 Region-Based Deployment

- Kullanici verileri tenant'in sectigi region'da saklanir
- Desteklenen region'lar: EU (Frankfurt), US (Virginia), APAC (Singapore), TR (Istanbul)
- Cross-region veri transferi YASAK (GDPR Art. 44-49)
- Encryption key'ler region-local KMS'te uretilir ve saklanir
- Backup'lar ayni region'da
- Log'lar ayni region'da

### 35.2 DPA (Data Processing Agreement)

- Her tenant ile DPA imzalanir (GDPR Art. 28)
- Sub-processor listesi seffaf
- Veri isleme amaci ve kapsamini acikca tanimlar

---

## 36. Altyapi Guvenligi & Operasyonel Prosedurler

### 36.1 Backup & Disaster Recovery

- **RPO** (Recovery Point Objective): Max 1 saat veri kaybi
- **RTO** (Recovery Time Objective): Max 4 saat restore suresi
- PostgreSQL: Continuous WAL archiving + PITR (Point-in-Time Recovery)
- Redis: AOF persistence + snapshot
- Backup'lar sifreli (AES-256-GCM), ayri region'da kopya
- DR testi: 6 ayda bir tam restore testi (SOC 2 kaniti)

### 36.2 Network Segmentation

- Auth server kendi VPC/subnet'inde (PCI DSS zorunlu)
- Database public internet'ten erisilemez
- Bastion host / VPN uzerinden admin erisimi
- Security group'lar: sadece gerekli portlar acik

### 36.3 Change Management

- Tum kod degisiklikleri PR + code review + approval (min 1 reviewer)
- Staging ortaminda test zorunlu
- Rollback proseduru dokumante
- Emergency change proseduru (P1 icin hizlandirilmis, ama yine loglanir)

### 36.4 Incident Response Plan

1. **Detection**: Monitoring + alerting ile tespit
2. **Triage**: Severity belirleme (P1-P4)
3. **Containment**: Etkilenen sistemi izole et
4. **Eradication**: Root cause'u gider
5. **Recovery**: Sistemi normal duruma getir
6. **Post-mortem**: Olay sonrasi analiz, lessons learned
- GDPR breach notification: 72 saat icinde supervisory authority'ye
- Yilda 1 tabletop exercise (SOC 2 kaniti)

### 36.5 Vulnerability Management

- Dependency scanning: Her CI/CD pipeline'inda (npm audit, Snyk, Trivy)
- Container image scanning: Her build'de
- DAST (Dynamic Application Security Testing): Aylik
- Penetration testing: Yillik (3rd party, PCI DSS zorunlu)
- Remediation SLA: Critical = 7 gun, High = 30 gun, Medium = 90 gun

---

## 37. i18n & Accessibility

### 37.1 Internationalization

- Hata mesajlari: 10+ dil destegi (en, tr, de, fr, es, ar, zh, ja, ko, pt minimum)
- Email template'leri: Tenant + dil bazinda
- SMS icerikleri: Dil bazinda
- Login/register sayfalari: RTL (sagdan sola) destegi (Arapca, Ibranice)
- Tarih/saat formati: Locale-aware
- Telefon numarasi formati: E.164 + ulke kodu destegi

### 37.2 Accessibility (WCAG 2.1 AA)

- Login/register sayfalari WCAG 2.1 AA uyumlu
- Screen reader destegi (ARIA labels)
- Keyboard navigation (tab order, focus management)
- Renk kontrast oranlari (min 4.5:1)
- Form validation hatalari acik ve anlasilir
- CAPTCHA alternatifleri (Proof-of-Work, gorunmez dogrulama)

---

## 38. SaaS Platform & Business Model

### 16.1 Deployment Modelleri

| Model | Aciklama | Hedef Kitle |
|-------|----------|-------------|
| **SaaS (Managed)** | Biz host ediyoruz, dashboard'dan proje olustur | Startup, SMB, mid-market |
| **Self-Hosted** | Docker/Helm ile kendi sunucusunda | Regulated industries, on-prem gereksinimleri |
| **Private Cloud** | Dedicated instance, biz yonetiyoruz | Bankalar, fintech, devlet |

### 16.2 Fiyatlandirma

**Free (Starter)**
- 50,000 MAU
- 1 proje, 1 environment (dev)
- Email+password, social login (Google, GitHub), magic link
- TOTP MFA
- Audit log (7 gun retention)
- Community destek
- `*.authserver.dev` subdomain
- "Powered by AuthServer" branding

**Pro — $49/ay**
- 100,000 MAU dahil, asim: $0.005/MAU
- 5 proje, dev + prod environment
- Tum auth yontemleri (passkeys, SMS OTP dahil)
- Blocking hooks (5 endpoint)
- Webhook (5 endpoint)
- Custom domain (1)
- Branding kaldirma
- Audit log (30 gun retention)
- Email destek (48 saat SLA)

**Business — $249/ay**
- 250,000 MAU dahil, asim: $0.004/MAU
- 20 proje
- Organizations + RBAC
- Enterprise SSO (SAML/OIDC, 3 connection dahil, ek: $50/ay/connection)
- SCIM provisioning
- Blocking hooks (sinirsiz)
- Webhook (sinirsiz) + DLQ + replay
- Custom domain (5)
- Risk engine + step-up auth
- Admin impersonation
- Audit log (90 gun retention) + export
- SOC 2 raporu erisimi
- Priority destek (24 saat SLA)

**Enterprise — Custom**
- Sinirsiz MAU (volume discount)
- Sinirsiz proje
- DPoP / FAPI 2.0
- Device attestation + transaction authorization (PSD2 SCA)
- Multi-region data residency
- 99.99% SLA
- HIPAA BAA, PCI DSS uyumu
- FedRAMP (opsiyonel, +%25)
- Dedicated Slack + customer success engineer
- Onboarding + migration destegi
- Custom contract

**Self-Hosted Lisans**
- Community Edition: Ucretsiz, acik kaynak cekirdek
- Enterprise License: $999/ay flat fee (sinirsiz kullanici)

**Anti-patterns (YAPMAYACAGIMIZ):**
- Otomatik tier upgrade yok (Auth0'un 1 numarali sikayeti)
- MAU asiminda hizmet kesintisi yok, uyari gonderilir
- MFA paywall arkasinda degil (guvenlik herkesin hakki)
- Branding kaldirmak icin ayri ucret yok (Pro'da dahil)

### 16.3 Proje & API Key Yapisi

```
Account (kullanici veya takim)
  |-- Proje: "My SaaS App"
  |     |-- Development
  |     |     |-- pk_test_xxxxx (public key, client SDK icin)
  |     |     |-- sk_test_xxxxx (secret key, server SDK icin)
  |     |     |-- Ayri user pool, gevsetilmis rate limit
  |     |
  |     |-- Production
  |           |-- pk_live_xxxxx
  |           |-- sk_live_xxxxx
  |           |-- Ayri user pool, tam guvenlik
  |
  |-- Proje: "Mobile App"
        |-- Development / Production
```

- Key'ler revoke + rotate edilebilir (zero-downtime)
- Dev'de email yerine console log secenegi
- Prod'a gecis: tek tikla konfigurasyon kopyalama

### 16.4 Dashboard Rolleri

| Rol | Billing | Takim | Prod Config | Dev Config | Kullanici Verisi | Log |
|-----|---------|-------|-------------|------------|------------------|-----|
| Owner | Tam | Tam | Tam | Tam | Tam | Tam |
| Admin | Goruntule | Ekle/Cikar | Tam | Tam | Tam | Tam |
| Developer | - | - | Salt okunur | Tam | Goruntule | Goruntule |
| Viewer | - | - | - | - | Goruntule | Goruntule |

Dashboard'a giris: Google/GitHub SSO veya email+MFA. Enterprise: Kendi SAML/OIDC IdP'si ile.

### 16.5 Dashboard Sayfalari

**Overview (Ana Sayfa)**
- MAU trend grafigi + mevcut kullanim
- Son 24 saat: login basari/basarisizlik orani
- Aktif session sayisi
- Alert'ler (brute force, anomali, MAU uyari)
- Quick links: API key'ler, docs, quickstart

**Users**
- Liste: arama, filtreleme (auth yontemi, MFA durumu, son giris)
- Detay: profil, session'lar, login gecmisi, MFA, custom claims
- Aksiyonlar: ban, password reset, MFA reset, impersonate (Business+)
- Import (CSV/JSON) + Export (GDPR)

**Authentication**
- Toggle switch'ler: Email+Pass, Google, Apple, GitHub, Microsoft, Magic Link, Passkeys, SMS OTP, TOTP
- Her provider icin konfigürasyon (Client ID, Secret, scope)
- Password policy ayarlari
- Session policy ayarlari (idle timeout, absolute timeout, concurrent limit)

**Hooks & Webhooks**
- Blocking hooks: endpoint URL, secret, test, loglar, failure mode
- Webhooks: endpoint, event secimi, delivery loglar, DLQ, replay

**Organizations (Business+)**
- Org listesi + olusturma
- Member yonetimi, davet, roller
- Per-org SSO (SAML metadata upload, OIDC discovery)
- SCIM endpoint durumu

**Audit Logs**
- Real-time stream
- Filtre: event tipi, kullanici, IP, tarih, sonuc
- Export (JSON/CSV)
- "Verify Integrity" butonu (hash chain dogrulama)

**Security**
- Risk engine: esik degerleri, aksiyonlar
- IP whitelist/blacklist
- Geo-blocking (ulke bazli)
- Bot detection ayarlari
- Device attestation sonuclari (Enterprise)

**Analytics**
- Auth yontemi dagilimi (pie chart)
- MFA adoption orani (trend)
- Login basari/basarisizlik trendi
- Session dagilimi: cihaz, ulke, tarayici
- Risk score dagilimi

**Settings**
- Proje bilgileri
- Custom domain + TLS durumu
- Email template editoru (visual + HTML)
- Email/SMS provider konfigurasyonu
- Branding: logo, renkler, login sayfasi onizleme
- CORS allowed origins
- Redirect URL whitelist
- Dil ayarlari

**Billing (Owner)**
- Plan + kullanim
- MAU trend + tahmin
- Fatura gecmisi
- Odeme yontemi
- Plan degisikligi

### 16.6 Onboarding Akisi

**Hedef: Signup -> ilk basarili login = 5 dakika**

```
1. Signup (Google/GitHub veya email)
2. "Projenizi olusturun" — isim + platform (Web/Mobile/Backend)
3. Framework sec (Next.js, React, Vue, Express, NestJS, React Native, Flutter, vb.)
4. Quickstart sayfasi:
   a. npm install @authserver/client
   b. API key goster (pk_test_xxx) — kopyala
   c. 10-15 satirlik ornek kod — kopyala
   d. "Test edin" butonu — dashboard'da canli login izle
5. "Ilk kullanicimiz olusturuldu!" + sonraki adimlar
```

**Interactive playground:**
- Dashboard icinde canli API tester
- curl komutlari projeye ozel key'ler ile otomatik dolu
- SDK ornekleri key'ler ile dolu

### 16.7 Migration Araclari

**Import:**
- Auth0, Firebase, Supabase, Clerk export format destegi
- Generic CSV (email, password_hash, hash_algorithm)

**Password hash migration:**
- bcrypt, PBKDF2, Argon2 hash'leri direkt import
- SHA-256/MD5: Kullaniciya "sifrenizi yenileyin" maili
- Login'de otomatik Argon2id upgrade

**Zero-downtime strategy:**
1. Toplu import (hash'ler ile)
2. Yeni login'leri AuthServer'a yonlendir
3. Login'de hash upgrade
4. Eski sistemi kapat

---

## 39. Fonksiyonel Faz Plani

### Faz 0: Core Auth (Ay 1-2)

> Hedef: Piyasadaki servislerin %95'inden daha guvenli bir temel.

1. NestJS monorepo (server + client SDK + server SDK)
2. PostgreSQL + Redis altyapisi
3. Tenant yonetimi (temel CRUD, API key uretimi)
4. Email + Password (Argon2id + pepper + salt + HIBP + constant-time)
5. Email verification (OTP veya magic link)
6. Password reset (256-bit token, 15dk)
7. JWT access token (RS256, 30dk) + JWKS endpoint
8. Opaque refresh token (rotation + family-based revocation)
9. Session yonetimi (idle/absolute timeout, aktif session listesi)
10. Audit log (structured JSON, SHA-256 hash chain, PII encryption)
11. Rate limiting (Redis sliding window, per-IP + per-endpoint)
12. Security headers (HSTS, CSP, CORS, X-Frame-Options)
13. Request validation (body size, content-type, JSON depth)
14. Email altyapisi (pluggable provider, SPF/DKIM/DMARC rehberi)
15. Client SDK: signUp, signIn, signOut, getSession, getUser, onAuthStateChange, auto-refresh
16. Server SDK: verifyToken, admin.createUser, updateUser, deleteUser, listUsers

**Neden %95'inden guvenli:**
- Argon2id + pepper + salt (cogu sistem bcrypt bile kullanmiyor)
- HIBP kontrolu (neredeyse kimse yapmiyor)
- Token rotation + stolen token detection (family-based revocation)
- Tamper-evident audit log (hash chain)
- Constant-time comparison (timing attack korumasi)
- Security headers (cogu startup eksik)

**Sertifika:** NIST AAL1, GDPR temel

### Faz 1: MFA + Social + Hooks (Ay 3-4)

> Hedef: Firebase/Supabase seviyesi + blocking hooks avantaji.

1. TOTP MFA (QR enrollment, AES-256-GCM secret, backup codes)
2. Social login: Google, Apple, GitHub, Microsoft (Auth Code + PKCE)
3. Account linking (verified email ile otomatik)
4. Magic link (256-bit token, 15dk)
5. Blocking hooks (before.user.create, before.login + after variants)
6. Webhook sistemi (HMAC imza, retry, temel)
7. Session: device metadata binding, concurrent limit, remote revocation
8. Client SDK: signInWithOAuth, signInWithCredential, mfa.enroll/verify, recovery codes
9. Server SDK: hooks.before(), on(), admin.setCustomClaims, revokeAllSessions
10. Admin panel (temel): kullanici listesi, session yonetimi, konfigurasyon, log viewer

**Sertifika:** NIST AAL2, OpenID Basic OP basvurusu baslar

### Faz 2: Passkeys + Enterprise (Ay 5-7)

> Hedef: Clerk/WorkOS seviyesi. FIDO2 + OpenID sertifika basvurulari.

1. WebAuthn/Passkeys (packed+none attestation, ES256, counter validation, MDS v3)
2. Passkey-first kayit + cross-device QR login
3. Step-up auth (ACR/AMR claims, per-endpoint seviye)
4. Risk engine (IP geo, impossible travel, device fingerprint, VPN/Tor, velocity)
5. Organizations (CRUD, member management, roller, davet)
6. OpenID Connect Provider (discovery, auth code+PKCE, token, userinfo, JWKS, logout)
7. Token introspection (RFC 7662) + revocation (RFC 7009)
8. Key rotation (JWKS'te eski+yeni, kid bazli)
9. Bot detection (Proof-of-Work, credential stuffing tespiti)
10. SMS OTP (pluggable provider, ulke whitelist)
11. NestJS SDK (@RequireAuth, @CurrentUser, hook handler interface)
12. Edge SDK (<50KB, JWKS cache, JWT verify, Cloudflare Workers + Vercel Edge)

**Sertifika:** FIDO2 basvuru, OpenID Basic OP, SOC 2 gozlem baslar

### Faz 3: Financial-Grade (Ay 8-12)

> Hedef: Auth0 seviyesi + device attestation + PSD2 SCA.

1. DPoP (ephemeral key, proof JWT, cnf.jkt claim)
2. PAR (Pushed Authorization Requests)
3. Device attestation (Play Integrity API, Apple App Attest)
4. Cryptographic device binding (hardware enclave key pair)
5. Transaction authorization (PSD2 SCA dynamic linking, WYSIWYS)
6. SAML 2.0 (SP + IdP modu, XXE korumasi)
7. Enterprise SSO per org (SAML/OIDC, self-service setup UI)
8. SCIM 2.0 provisioning (per-org endpoint)
9. API key + M2M auth (client_credentials, PATs)
10. OpenID FAPI 2.0 (PAR + PKCE + DPoP)
11. GDPR DSAR endpoint'leri (export, delete, consent)
12. Breach detection (HIBP monitoring, credential stuffing)
13. Admin panel: org yonetimi, SSO konfig, webhook DLQ, risk dashboard

**Sertifika:** FIDO2 alinir, FAPI basvuru, SOC 2 gozlem devam

### Faz 4: Scale + Compliance (Ay 13-18)

> Hedef: SOC 2 raporu alma. Multi-region, full enterprise.

1. Multi-region deployment (data residency: EU, US, APAC, TR)
2. Custom domain per tenant (Let's Encrypt/ACME)
3. White-label (login sayfalari, email template'ler, branding)
4. Advanced risk engine (3rd party connectors, behavioral signals)
5. Admin impersonation (RFC 8693 token exchange, audit trail)
6. Advanced webhook (DLQ, replay, fan-out, delivery logs)
7. Backup & DR (PITR, encrypted backup, 6 aylik DR test)
8. Vulnerability management (dependency scan, DAST, pentest)
9. Incident response plan (documented, yillik exercise)
10. Change management proseduru
11. i18n (en, tr + framework)

**Sertifika:** SOC 2 Type II ALINIR, ISO 27001 baslar, PCI DSS gap analysis

### Faz 5: Global Compliance (Ay 19-30)

> Hedef: Tam sertifika portfolyosu. Piyasada esdegeri olmayan platform.

1. ISO 27001 sertifikasi
2. PCI DSS v4.0 sertifikasi
3. HIPAA BAA
4. CSA STAR Level 2
5. FedRAMP High basvurusu
6. eIDAS LoA High (QTSP entegrasyonu)
7. AI Agent / MCP auth (agent entity, OAuth 2.1, RFC 8693 token exchange)
8. EUDI Wallet (OpenID4VP, selective disclosure)
9. Continuous auth (behavioral signals -> risk engine)
10. KYC entegrasyon hook'lari
11. Full i18n (10+ dil, RTL)
12. WCAG 2.1 AA

**Sertifika:** ISO 27001, PCI DSS, HIPAA, CSA STAR, FedRAMP suruyor, FAPI 2.0, eIDAS

### Faz Ozet

| Faz | Sure | Piyasa Esdegeri | Sertifika |
|-----|------|-----------------|-----------|
| **0** | Ay 1-2 | %95'inden guvenli | NIST AAL1, GDPR |
| **1** | Ay 3-4 | Supabase/Firebase + hooks | NIST AAL2, OpenID basvuru |
| **2** | Ay 5-7 | Clerk/WorkOS + FIDO2 | FIDO2 + OpenID basvuru, SOC 2 gozlem |
| **3** | Ay 8-12 | Auth0 + PSD2 SCA + device attestation | FIDO2, FAPI basvuru |
| **4** | Ay 13-18 | Descope seviyesi | SOC 2 alinir, ISO + PCI baslar |
| **5** | Ay 19-30 | Piyasada esdegeri YOK | Tam portfolyo |
