# PalAuth — Development Rules

## Project

Self-hosted authentication server. Go backend, Next.js dashboard, multi-language SDK'lar.

```
cmd/server/          → Go main binary
internal/            → Core logic (auth, token, session, hook, audit, crypto, ...)
api/openapi.yaml     → OpenAPI spec (source of truth — SDK'lar buradan generate edilir)
migrations/          → SQL migration dosyalari (goose)
dashboard/           → Next.js admin panel
sdk/                 → SDK'lar (typescript, go, mobile)
phases/              → Faz planlari (phase-0.md ... phase-7.md)
docker/              → Docker + Compose dosyalari
helm/                → Kubernetes Helm chart
```

## Specs

Kod yazmadan once ilgili spec'i oku:
- `spec.md` — Core fonksiyonalite, tum bolumler
- `spec-compliance.md` — Sertifika, regulasyon, uyum gereksinimleri
- `spec-sdk.md` — SDK tasarimi
- `packages.md` — Go paket listesi (final, degismeyecek)
- `phases/phase-N.md` — Mevcut fazin detayli task listesi

## Language & Framework

- **Server**: Go 1.26+
- **Dashboard**: Next.js 15, shadcn/ui, Tailwind, React Query
- **Mobile SDK**: Kotlin Multiplatform (KMP)
- **SDK'lar**: TypeScript (client, server, nestjs, edge)

## Go Conventions

- Chi router (v5.2.5) — net/http uyumlu, middleware composition
- pgx v5 + sqlc — type-safe SQL, ORM yok
- goose — SQL migration
- koanf — config (env var + yaml)
- slog — structured logging (stdlib)
- go-jose v4 — JOSE/JWK/JWT
- testify + testcontainers-go + rapid — testing

## Security Rules (TUM FAZLARDA GECERLI)

### Password
- Argon2id + HMAC-SHA256 pepper (alexedwards/argon2id)
- Min 15 char single-factor, 8 char with MFA (NIST 800-63B-4)
- Max 64 char, truncate YASAK
- Composition rules UYGULANMAZ (NIST SHALL NOT)
- HIBP k-Anonymity kontrolu ZORUNLU
- Son 4 sifre tekrar yasak (PCI DSS v4.0.1 Req 8.3.7)
- Constant-time comparison ZORUNLU (crypto.timingSafeEqual / subtle.ConstantTimeCompare)
- Pepper env var'dan: `PALAUTH_PEPPER` (server baslamazsa bos ise)

### Token
- JWT signing: PS256 veya ES256 (go-jose v4). FAPI modunda RS256 YASAK
- Access token: 30dk default, FAPI modunda 5dk
- Refresh token: Opaque 256-bit, SHA-256 hash DB'de, 30sn grace period
- Family-based revocation: Eski token reuse → tum family revoke
- `auth_time` claim ZORUNLU (RFC 9068)
- `kid` header ZORUNLU

### Session
- AAL-based timeout (NIST 800-63B-4 Rev 4):
  - AAL1: idle yok, absolute SHOULD 30 gun
  - AAL2: idle SHOULD 1 saat, absolute SHOULD 24 saat
  - AAL3: idle SHOULD 15dk, absolute SHALL 12 saat
- `acr` ve `amr` claims session create'te set edilir
- Session regeneration: Privilege escalation sonrasi

### Encryption
- AES-256-GCM envelope encryption (KEK + per-project DEK + per-user DEK)
- PII alanlari (email, telefon) AES-GCM ile sifreli saklanir
- Email lookup: deterministic hash (email_hash kolonu)
- TLS 1.2+ zorunlu (SSLv3, TLS 1.0, TLS 1.1 YASAK)

### Audit Log
- SHA-256 hash chain — CIPHERTEXT uzerinden (plaintext degil)
- Canonical JSON serialization (key'ler alfabetik sirali)
- PII alanlari per-user DEK ile sifreli
- GDPR erasure: DEK sil → PII okunamaz, chain bozulmaz
- `gdpr.erasure` event ZORUNLU (user delete'te)
- Non-PII metadata (event_type, target_type, auth_method) plaintext kalir

### Rate Limiting
- go-chi/httprate + httprate-redis (distributed)
- Login: 10/5dk per IP, 5/5dk per account
- Signup: 5/15dk per IP
- MFA: 5/5dk per account
- Password reset: 3/15dk per account
- Redis down → fail-open (rate limit icin)

### User Enumeration Prevention
- Login: var olmayan email ile ayni hata + ayni response time
- Signup: ayni email ile ayni hata mesaji
- Password reset: her zaman 200 doner
- Constant-time user lookup (user yoksa bile ayni sure)

### Lockout
- Password login: 10 basarisiz → 30dk lockout (PCI DSS Req 8.3.4)
- MFA: 5 basarisiz → 30dk lockout (PSD2 RTS)
- Transaction: 5 basarisiz → 30dk lockout
- Farkli threshold'lar KASITLI (MFA daha hassas)

### Inactive Accounts
- 90 gun login olmayan hesaplar devre disi (PCI DSS Req 8.2.6)
- Gunluk cron job, `admin.user.deactivate_inactive` audit event

## Error Response Format

Tum endpoint'ler ayni format:
```json
{
  "error": "invalid_credentials",
  "error_description": "Email or password is incorrect",
  "status": 401,
  "request_id": "req_xxx"
}
```
- `error`: Machine-readable kod (SDK'lar buna guvenebilir)
- `error_description`: Human-readable (i18n SDK tarafinda)
- `status`: HTTP status code
- `request_id`: Correlation (UUIDv7, middleware'den)

## HTTP Security Headers

Tum response'larda (middleware ile):
```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 0
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cache-Control: no-store, no-cache, must-revalidate  (auth endpoint'lerinde)
```

## ID Generation

- UUIDv7 (google/uuid) — time-ordered, PostgreSQL native uuid
- Prefix ile: `id.New("prj_")` → `prj_0192f5e0-7c1a-...`
- Prefixes: `prj_`, `usr_`, `sess_`, `rt_`, `key_`, `ph_`, `vt_`, `ek_`

## Database Conventions

- PostgreSQL 16+, pgx v5 driver
- Tum tablolarda `project_id` column (project izolasyonu)
- `created_at TIMESTAMPTZ NOT NULL DEFAULT now()` her tabloda
- FK references: `REFERENCES parent(id)` (audit_logs haric — append-only)
- Partial index kullan: `WHERE revoked_at IS NULL`, `WHERE used = false`
- Migration numara formati: `NNN_description.up.sql` (001-044)

## Hook System

- Blocking hooks (before.*): Pipeline durur, backend cevap bekler
- Non-blocking hooks (after.*): Fire-and-forget, webhook delivery
- HMAC-SHA256 bidirectional signing (Standard Webhooks spec)
- Timeout: 15sn default, configurable
- Failure mode: `deny_on_failure` (default, guvenli) veya `allow_on_failure`
- Client metadata: Client SDK'dan gonderilen extra JSON hook payload'da `client_metadata` field'inda erisilebilir

## Testing Rules

Her task kendi testini birlikte yazar. "Sonra test yazariz" YOK.

Spec Section 43 — 12 katman:
1. Unit tests → her push
2. Property-based (rapid) → her push
3. AI Security Review (Claude) → her PR
4. Integration (testcontainers-go) → her PR
5. Contract (Pact) → Faz 5+ (SDK'lar)
6. DAST (ZAP) → her PR baseline, aylik active
7. E2E (Playwright) → PR merge to main
8. Mutation (gremlins) → PR merge to main, guvenlik modulleri %80+
9. API Fuzzing (Go fuzz + RESTler) → haftalik
10. Chaos (Toxiproxy) → aylik
11. Load (k6) → haftalik
12. Conformance (OpenID/FIDO2/FAPI) → release oncesi

Coverage hedefleri:
- Guvenlik modulleri (crypto, token, auth, audit): %90+ line, %80+ mutation
- Genel: %85+ line

## Git Conventions

- Branch: `feat/T0.7-signup`, `fix/T0.9-lockout-timer`
- Commit: `feat(auth): implement signup with Argon2id + HIBP check [T0.7]`
- PR: Task ID referansi, kabul kriterleri checklist
- CODEOWNERS: Min 1 reviewer zorunlu
- `main` branch protected, direct push YASAK

## CI/CD Pipeline

```
push → lint (golangci-lint) + unit tests + property-based
PR   → + integration tests + DAST baseline + Claude Security Review
merge → + E2E (Playwright) + mutation (gremlins)
weekly cron → + full mutation + RESTler fuzzing + k6 load
monthly cron → + chaos (Toxiproxy) + DAST active scan
```

## Config

koanf v2 ile. Environment variables `PALAUTH_` prefix:
- `PALAUTH_PEPPER` — ZORUNLU, bos ise server baslamaz
- `PALAUTH_DATABASE_URL` — PostgreSQL connection string
- `PALAUTH_REDIS_URL` — Redis connection string
- `PALAUTH_FIPS` — FIPS 140-3 mode (true/false)
- `PALAUTH_EMAIL_PROVIDER` — console / smtp / ses / sendgrid
- `PALAUTH_LOG_LEVEL` — debug / info / warn / error
- `PALAUTH_LOG_FORMAT` — json / text

## Compliance Rules (TUM FAZLARDA KOD YAZARKEN UYULMALI)

Detay: `spec-compliance.md`

### NIST 800-63B-4
- AAL1/2/3 seviyelerine gore session timeout set et
- AAL2'de en az bir phishing-resistant secenek SUNULMALI (WebAuthn — SHALL)
- Compromised password check ZORUNLU (HIBP)
- Composition rules UYGULANMAZ (SHALL NOT)
- Periyodik rotation UYGULANMAZ (SHALL NOT)

### PCI DSS v4.0.1
- Req 8.3.4: 10 basarisiz → 30dk lockout
- Req 8.3.6: 15 char min (NIST ile birlikte)
- Req 8.3.7: Son 4 sifre tekrar yasak
- Req 8.2.6: 90 gun inaktif hesap devre disi
- Req 8.6.1-8.6.3: Service account unique ID, no hard-coded creds, rotation + TTL
- Req 6.4.2: WAF zorunlu (public-facing)
- v4.0 RETIRED (31 Aralik 2024) — sadece v4.0.1 referans ver

### FAPI 2.0 (FAPI modu aktifken)
- Algoritmalar: SADECE PS256, ES256, EdDSA. RS256 YASAK
- Auth code max 60sn
- PAR zorunlu, request_uri < 600sn
- Sadece confidential client
- HTTP 307 redirect YASAK (303 kullan)
- `iss` parameter zorunlu (RFC 9207)
- Sender-constrained token zorunlu (DPoP veya mTLS)
- Refresh token rotation SHALL NOT — sender-constraining ile guvenlik

### PSD2/PSD3 SCA
- Iki bagimsiz faktor (knowledge + possession + inherence)
- Dynamic linking: Tutar + alici auth code'a bagli
- WYSIWYS: Kullanici neyi gorduyse onu imzalar
- Max 5dk auth code/OTP omru
- Max 5 basarisiz deneme

### GDPR
- Data minimization: Sadece gerekli veri topla
- Right to erasure: Cryptographic erasure (DEK sil, chain bozulmaz)
- Data portability: JSON export endpoint
- Consent: Granular, verme = geri cekme kadar kolay
- Breach notification: 72 saat
- Pseudonymization: Audit log PII sifreli
- DPIA: Deployment oncesi tamamlanmali

### SOC 2
- Tum auth event'leri audit logda
- Immutable log (hash chain)
- Ceyreklik access review
- Yillik pentest
- Change management (PR + review + approval)
- Evidence collection otomatik (CI/CD loglar)

### DORA (AB finans sektoru)
- Sozlesme: SLA, exit plan, denetim haklari
- Incident reporting: 4 saat ilk bildirim, max 24 saat, 72 saat ara rapor, 1 ay nihai rapor
- Is surekliligi testi: yillik (+ onemli ICT degisiklikleri sonrasi). TLPT: 3 yilda bir
- Cikis stratejisi ve denetim haklari zorunlu

### FIPS 140-3 (FIPS modu aktifken)
- Go 1.26 native FIPS module
- Approved algoritmalar: AES, SHA-2, HMAC, RSA 2048+, ECDSA, EdDSA
- YASAK: Chacha20, MD5, SHA-1 (signing), RSA 1024
- Argon2id FIPS-approved DEGIL → PBKDF2-HMAC-SHA256 (600K+ iteration)

## Agent Team Workflow

When the user asks to implement ANY task, ALWAYS create an agent team and spawn teammates. Never use subagents for development work. This is not optional.

Three teammate definitions live in `.claude/agents/`:

| Teammate | Role |
|----------|------|
| `coder` | Implements code and tests |
| `code-reviewer` | Code quality + architecture review |
| `security-reviewer` | Security + compliance review |

### Automatic Workflow

On ANY implementation request (e.g. "implement T0.4", "kodla", "write the signup handler"):

1. Create an agent team
2. Spawn ALL three teammates at once: `coder`, `code-reviewer`, `security-reviewer`
3. Coder implements the task. Code-reviewer and security-reviewer wait.
4. Coder must verify ALL acceptance criteria from the phase spec before signaling done. Every criterion must be implemented AND have a passing test. Coder messages lead with: files changed, acceptance criteria checklist, test results.
5. Lead verifies coder's acceptance criteria report — if anything is missing, message coder to complete it before proceeding to review
6. Lead messages code-reviewer to start reviewing
7. Code review NEEDS_CHANGES → code-reviewer messages coder directly → coder fixes → coder messages code-reviewer directly → **LOOP until code-reviewer PASS**
8. Code-reviewer PASS → code-reviewer messages security-reviewer to start
9. Security review NEEDS_CHANGES → security-reviewer messages coder directly → coder fixes → coder messages code-reviewer to re-check → **if code-reviewer NEEDS_CHANGES, coder fixes, LOOP** → code-reviewer PASS → coder messages security-reviewer → **LOOP until security-reviewer PASS**
10. Security-reviewer PASS → security-reviewer messages code-reviewer for final quality check
11. Final quality NEEDS_CHANGES → code-reviewer messages coder → fix loop restarts
12. Final quality PASS → code-reviewer messages security-reviewer for final sign-off
13. Final sign-off PASS → security-reviewer messages lead → **lead does final verification and cleanup**:
    - Verify all acceptance criteria from the phase spec are met
    - Update the phase file: check off completed acceptance criteria (`- [x]`)
    - Synthesize results, close task

Teammates talk to each other directly. Lead does NOT relay messages between them. Lead only: spawns the team, verifies acceptance criteria, triggers the first review, and does final cleanup.

### Review Loop Diagram

```
                    ┌─────────────────────────────────┐
                    │                                  │
                    ▼                                  │
coder writes ──► code-reviewer ──NEEDS_CHANGES──► coder fixes
                    │                                  ▲
                    PASS                               │
                    ▼                                  │
              security-reviewer ──NEEDS_CHANGES──► coder fixes ──► code-reviewer re-check
                    │                                  ▲               │
                    PASS                               │          NEEDS_CHANGES
                    ▼                                  │               │
              code-reviewer final ──NEEDS_CHANGES──────┘               │
                    │                                                  │
                    PASS                                               │
                    ▼                                                  │
              security-reviewer final sign-off ◄───────────────────────┘
                    │
                    PASS
                    ▼
                   DONE
```

The loop continues until security-reviewer gives final sign-off. Every fix by the coder must be re-validated by the relevant reviewer before moving forward. No shortcutting — if a security fix breaks architecture, it goes back through code review.

### Rules

- ALWAYS spawn teammates, NEVER use subagents for implementation/review
- Spawn ALL three teammates upfront — they communicate directly with each other, lead is not a middleman
- Coder must verify ALL acceptance criteria (Kabul kriterleri) from the phase spec before signaling done — every criterion must be implemented AND have a passing test
- The loop is the law: every fix gets re-reviewed, no exceptions
- ALL issues must be fixed — reviewers do NOT give PASS with any open issues, regardless of severity
- Security fixes that touch architecture → code-reviewer must re-check
- Code-reviewer fixes that touch security logic → security-reviewer must re-check
- Reviewers can message each other directly when concerns overlap
- If a single review stage exceeds 3 iterations, lead intervenes
- Task is NOT done until security-reviewer gives final sign-off
- After final sign-off, lead verifies acceptance criteria and updates the phase file (checks off completed criteria with `- [x]`)
- After everything is done, lead creates a git commit following repo conventions (e.g. `feat(auth): implement X [T0.N]`)

## Do NOT

- Hardcode secrets (PCI DSS 8.6.2 — YASAK)
- Use RS256 for JWT signing (FAPI 2.0 — YASAK)
- Use Math.random for security values (crypto/rand ZORUNLU)
- Store password plaintext or reversible (Argon2id one-way ZORUNLU)
- Return different errors for existing vs non-existing users (enumeration)
- Skip audit log for auth events (SOC 2 — tum event'ler loglanir)
- Use TLS < 1.2 (PCI DSS — YASAK)
- Allow wildcard CORS origin (YASAK)
- Trust client-side data without server validation
- Skip hook call before auth operations (blocking pipeline ZORUNLU)
- Use composition rules for passwords (NIST SHALL NOT)
- Implement periodic password rotation (NIST SHALL NOT, MFA aktifse PCI DSS de gerektirmez)
