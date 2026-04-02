# PalAuth Security Scan Instructions

This is a self-hosted, certification-ready authentication server targeting financial-grade security (NIST 800-63B-4, PCI DSS v4.0.1, FAPI 2.0, GDPR, SOC 2).

## Critical Rules — Flag violations immediately

### Password
- Must use Argon2id with HMAC-SHA256 pepper (PBKDF2 under FIPS mode only)
- Pepper loaded from env var `PALAUTH_PEPPER` — hardcoded pepper is CRITICAL
- Min 15 chars single-factor, 8 with MFA (NIST 800-63B-4)
- HIBP k-Anonymity check is mandatory
- Last 4 passwords must not be reused (PCI DSS v4.0.1 Req 8.3.7)
- Constant-time comparison via `subtle.ConstantTimeCompare` — timing side-channels are CRITICAL
- No composition rules enforced (NIST SHALL NOT)

### Token & JWT
- Signing algorithms: PS256 or ES256 only. RS256 is PROHIBITED (FAPI 2.0)
- `kid` header and `auth_time` claim are mandatory (RFC 9068)
- Refresh tokens: opaque 256-bit, SHA-256 hash stored in DB — never store plaintext
- Family-based revocation on token reuse — missing this is CRITICAL
- `crypto/rand` for all security values — `math/rand` is always CRITICAL

### User Enumeration Prevention
- Login/signup must return same error + same response time for existing vs non-existing users
- Password reset must always return 200
- Dummy Argon2id hash for non-existent users to equalize timing

### Rate Limiting & Lockout
- Login: 10/5min per IP, 5/5min per account
- MFA: 5/5min per account (stricter than password — intentional)
- Password lockout: 10 failed attempts -> 30min (PCI DSS Req 8.3.4)
- MFA lockout: 5 failed attempts -> 30min (PSD2 RTS)

### Audit Logging
- SHA-256 hash chain computed over ciphertext (not plaintext)
- Canonical JSON serialization (alphabetical keys)
- PII fields encrypted with per-user DEK
- ALL auth events must be logged (SOC 2)
- `gdpr.erasure` event mandatory on user deletion

### Encryption
- AES-256-GCM envelope encryption (KEK -> project DEK -> user DEK)
- PII fields (email, phone) encrypted at rest
- Deterministic email_hash column for lookups
- TLS 1.2+ mandatory — TLS 1.0, 1.1, SSLv3 are PROHIBITED

### HTTP Security
- Required headers: HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
- Cache-Control: no-store on all auth endpoints
- No wildcard CORS origins

## Do NOT flag

- Denial of Service concerns (handled by infrastructure)
- Missing rate limiting on non-auth endpoints
- Generic input validation without proven impact
- Code in `dashboard/`, `sdk/`, `docs/`, `helm/` directories
