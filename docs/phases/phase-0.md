# PalAuth — Faz 0: Core Auth (Ay 1-4)

> Hedef: Piyasadaki servislerin %95'inden daha guvenli bir temel. `docker compose up` ile ayaga kalkar.
> 18 task, 16 hafta. Go 1.26+, PostgreSQL 16+, Redis 7+.
> Her task kendi testini birlikte yazar (TDD). T0.17 final test sweep (coverage, fuzz, security).

---

## Go Paket Listesi (Final — Tum Fazlar Dahil, Degismeyecek)

> Tum paketler go.mod'a Faz 0'dan eklenir. Hic bir faz'da paket degisikligi yapilmaz.
> Detayli referans: [packages.md](../packages.md)

**Core:**

| Kategori | Paket | Versiyon |
|----------|-------|---------|
| Router | `go-chi/chi` | v5.2.5 |
| DB driver | `jackc/pgx` | v5.8.0 |
| Query codegen | `sqlc-dev/sqlc` | v1.30.0 |
| Migrations | `pressly/goose` | v3.27.0 |
| Redis | `redis/go-redis` | v9.18.0 |
| JOSE (JWK/JWE/JWS) | `go-jose/go-jose` | v4.1.3 |
| JWT | `golang-jwt/jwt` | v5.3.1 |
| Password hash | `alexedwards/argon2id` | latest |
| Validation | `go-playground/validator` | v10 |
| Config | `knadh/koanf` | v2.3.4 |
| Logging | `log/slog` + `samber/slog-multi` | Go 1.26 |
| Rate limiting | `go-chi/httprate` + `httprate-redis` | latest |
| CORS | `rs/cors` | v1.11.1 |
| ID generation | `google/uuid` (UUIDv7) | latest |
| OpenAPI codegen | `oapi-codegen/oapi-codegen` | v2.6.0 |
| Metrics | `prometheus/client_golang` | v1.23.2 |
| Events | `ThreeDotsLabs/watermill` | v1.5.1 |

**Auth Protokolleri:**

| Kategori | Paket | Versiyon |
|----------|-------|---------|
| OIDC Provider | `zitadel/oidc` | v3.45.6 |
| WebAuthn/Passkeys | `go-webauthn/webauthn` | v0.16.1 |
| TOTP | `pquerna/otp` | v1.5.0 |
| QR Code | `skip2/go-qrcode` | latest |
| OAuth2 client | `golang.org/x/oauth2` | v0.36.0 |
| SAML 2.0 | `crewjam/saml` | v0.5.1 |
| DPoP | `AxisCommunications/go-dpop` | v1.1.2 |
| SCIM 2.0 | `elimity-com/scim` | latest |

**Platform Entegrasyonlari:**

| Kategori | Paket | Versiyon |
|----------|-------|---------|
| IP Geolocation | `oschwald/geoip2-golang` | v2.1.0 |
| Play Integrity | `google.golang.org/api/playintegrity/v1` | latest |
| App Attest | `splitsecure/go-app-attest` | latest |
| ACME/TLS | `caddyserver/certmagic` | v0.25.2 |

**Testing:**

| Kategori | Paket | Versiyon |
|----------|-------|---------|
| Test framework | `stretchr/testify` | v1.11.1 |
| Mock generation | `vektra/mockery` | v3.7.0 |
| Integration test | `testcontainers/testcontainers-go` | v0.41.0 |
| Property-based | `flyingmutant/rapid` | latest |

---

## Oncelik Sirasi

Her task kendi unit/integration testini birlikte yazar. T0.17 final sweep — coverage, fuzz, security testleri.

---

## T0.1 — Proje Scaffold + CI/CD + Dev Ortami

**Ne:** Go monorepo yapisini olustur, CI/CD pipeline kur, dev docker-compose ile gelistirme ortamini ayaga kaldir.

**Yapilacaklar:**
- Go module init (`github.com/palauth/palauth`)
- Dizin yapisi:
  ```
  cmd/server/main.go
  internal/
    config/config.go        ← koanf ile konfigurasyon yonetimi
  pkg/
  api/openapi.yaml
  migrations/
  docker/
    docker-compose.yml      ← DEV: postgres + redis (Go server lokal calisir)
    docker-compose.prod.yml ← PROD: Go server + dashboard + postgres + redis
    Dockerfile.server
  .github/workflows/ci.yml
  ```
- `internal/config/config.go` — koanf v2 ile:
  - Environment variables (`PALAUTH_*` prefix)
  - YAML config file (opsiyonel)
  - Defaults: port=3000, pepper (zorunlu). Session timeout'lari AAL-based dinamik (T0.13'te uygulanir: AAL1=idle yok/abs 30gun, AAL2=idle 1sa/abs 24sa, AAL3=idle 15dk/abs 12sa)
  - Struct-based: `Config.Server.Port`, `Config.Database.URL`, `Config.Redis.URL`, `Config.Auth.PasswordMinLength`
- Makefile: `make build`, `make test`, `make lint`, `make migrate`, `make dev` (air hot reload)
- `make dev` → docker-compose ile postgres+redis ayaga kaldir + `air` ile Go server hot reload
- GitHub Actions: lint (golangci-lint) + test + build on push/PR
- Claude Code Security Review GitHub Action (`.github/workflows/security-review.yml`)
- `.golangci.yml` konfigurasyon (strict security rules: gosec, gocritic, errcheck)
- `go.mod` + temel dependency'ler
- `.env.example` — tum zorunlu env var'lar dokumante

**Kabul kriterleri:**
- [ ] `make build` basarili — tek binary uretir
- [ ] `make test` basarili — bos test suite calisir
- [ ] `make lint` basarili — golangci-lint gecer
- [ ] `make dev` → postgres+redis ayaga kalkar, Go server hot reload ile calisir
- [ ] GitHub Actions PR'da calisir (lint + test + build + security review)
- [ ] Config koanf ile yuklenebiliyor (env var + yaml + defaults)
- [ ] `PALAUTH_PEPPER` set edilmemisse server baslamayi reddeder

**Bagimlilk:** Yok (ilk task)

---

## T0.2 — HTTP Server + Router + Middleware

**Ne:** Chi router ile HTTP server, temel middleware zinciri.

**Yapilacaklar:**
- `internal/server/server.go` — HTTP server lifecycle (start, graceful shutdown)
- Chi router setup
- Middleware zinciri:
  - Request ID (UUIDv7)
  - Structured logging (slog)
  - Recovery (panic handler)
  - CORS via `rs/cors` (project bazinda whitelist — simdilk hardcoded, sonra DB'den)
  - Security headers (spec Section 37 tam liste):
    - `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
    - `Content-Security-Policy: default-src 'self'; script-src 'self'; frame-ancestors 'none'`
    - `X-Content-Type-Options: nosniff`
    - `X-Frame-Options: DENY`
    - `X-XSS-Protection: 0`
    - `Referrer-Policy: strict-origin-when-cross-origin`
    - `Permissions-Policy: camera=(), microphone=(), geolocation=()`
    - `Cache-Control: no-store, no-cache, must-revalidate` (auth endpoint'lerinde)
  - Request validation (body size 1MB, content-type check)
  - Response time tracking
- Standart error response format:
  ```go
  // internal/server/error.go
  type ErrorResponse struct {
    Error       string `json:"error"`             // machine-readable: "invalid_credentials"
    Description string `json:"error_description"` // human-readable
    Status      int    `json:"status"`            // HTTP status code
    RequestID   string `json:"request_id"`        // correlation
  }
  ```
  Tum endpoint'ler ayni format doner. SDK'lar bu formata guvenebilir.
- Health endpoints:
  - `GET /healthz` → 200 (liveness)
  - `GET /readyz` → 200 eger DB+Redis bagli (readiness)
- Prometheus metrics endpoint: `GET /metrics`

**Endpoint'ler:**
```
GET  /healthz
GET  /readyz
GET  /metrics
```

**Kabul kriterleri:**
- [ ] `curl localhost:3000/healthz` → 200
- [ ] Security headers tum response'larda var (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection:0, Referrer-Policy, Permissions-Policy, Cache-Control on auth endpoints)
- [ ] CORS dogru calisiyor (whitelist disindaki origin reddediliyor)
- [ ] Graceful shutdown calisiyor (SIGTERM → drain → exit)
- [ ] Request ID her response header'inda var
- [ ] slog ile structured JSON log ciktisi

**Bagimlilk:** T0.1

---

## T0.3 — Database + Migrations

**Ne:** PostgreSQL baglantisi (pgx), migration sistemi, temel tablolar.

**Yapilacaklar:**
- `internal/database/pool.go` — pgx connection pool (max 25 open, 10 idle, 30min lifetime)
- `internal/database/migrate.go` — goose entegrasyonu
- Ilk migration'lar (`migrations/`):
  ```sql
  -- 001_create_projects.up.sql
  CREATE TABLE projects (
    id          TEXT PRIMARY KEY NOT NULL,
    name        TEXT NOT NULL,
    config      JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
  );

  -- 002_create_users.up.sql
  CREATE TABLE users (
    id              TEXT PRIMARY KEY NOT NULL,
    project_id      TEXT NOT NULL REFERENCES projects(id),
    email_encrypted BYTEA NOT NULL,
    email_hash      BYTEA NOT NULL,  -- deterministic hash for lookup
    password_hash   TEXT,                 -- NULLABLE: passkey-first kayit icin (Faz 2'de sifresiz user olusturulabilir)
    email_verified  BOOLEAN NOT NULL DEFAULT false,
    banned          BOOLEAN NOT NULL DEFAULT false,
    ban_reason      TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}',
    last_login_at   TIMESTAMPTZ,          -- inaktif hesap 90 gun kontrolu icin (PCI DSS Req 8.2.6)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  CREATE INDEX idx_users_project_email ON users(project_id, email_hash);
  CREATE INDEX idx_users_inactive ON users(last_login_at) WHERE banned = false; -- 90 gun cron icin

  -- 003_create_sessions.up.sql
  CREATE TABLE sessions (
    id              TEXT PRIMARY KEY NOT NULL,
    project_id      TEXT NOT NULL REFERENCES projects(id),
    user_id         TEXT NOT NULL REFERENCES users(id),
    ip              TEXT,
    user_agent      TEXT,
    device_fp_hash  TEXT,
    acr             TEXT NOT NULL DEFAULT 'aal1',
    amr             JSONB NOT NULL DEFAULT '[]',
    idle_timeout_at TIMESTAMPTZ NOT NULL,
    abs_timeout_at  TIMESTAMPTZ NOT NULL,
    last_activity   TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  CREATE INDEX idx_sessions_user ON sessions(user_id) WHERE revoked_at IS NULL;

  -- 004_create_refresh_tokens.up.sql
  CREATE TABLE refresh_tokens (
    id          TEXT PRIMARY KEY NOT NULL,
    session_id  TEXT NOT NULL REFERENCES sessions(id),
    user_id     TEXT NOT NULL REFERENCES users(id),
    token_hash  BYTEA NOT NULL UNIQUE,
    family_id   TEXT NOT NULL,
    parent_id   TEXT,
    used        BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
  );
  CREATE INDEX idx_rt_token ON refresh_tokens(token_hash);
  CREATE INDEX idx_rt_family ON refresh_tokens(family_id);

  -- 005_create_api_keys.up.sql
  CREATE TABLE api_keys (
    id          TEXT PRIMARY KEY NOT NULL,
    project_id  TEXT NOT NULL REFERENCES projects(id),
    key_hash    BYTEA NOT NULL UNIQUE,
    key_prefix  TEXT NOT NULL,  -- 'pk_test_', 'sk_live_' etc
    key_type    TEXT NOT NULL CHECK (key_type IN ('public_test', 'secret_test', 'public_live', 'secret_live')),
    name        TEXT,
    last_used   TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ
  );
  CREATE INDEX idx_apikeys_hash ON api_keys(key_hash) WHERE revoked_at IS NULL;

  -- 006_create_audit_logs.up.sql
  -- Not: project_id FK YOK — bilerek. Append-only tablo, FK constraint insert performansini dusurur.
  -- Ayrica GDPR erasure'da project silinse bile loglar kalir.
  CREATE TABLE audit_logs (
    id                  TEXT PRIMARY KEY,  -- UUIDv7
    project_id          TEXT NOT NULL,
    trace_id            TEXT,              -- request correlation ID
    event_type          TEXT NOT NULL,
    actor_encrypted     BYTEA,            -- PII: user_id, ip, user_agent, device_fp, geo (AES-GCM per-user DEK)
    target_type         TEXT,             -- plaintext: "session", "user", "token"
    target_id           TEXT,             -- plaintext: resource ID
    result              TEXT NOT NULL CHECK (result IN ('success', 'failure')),
    auth_method         TEXT,             -- plaintext: "password", "password+totp", "passkey"
    risk_score          REAL DEFAULT 0.0, -- 0.0-1.0
    metadata_encrypted  BYTEA,            -- ek PII (AES-GCM per-user DEK)
    prev_hash           TEXT,
    event_hash          TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  CREATE INDEX idx_audit_project_time ON audit_logs(project_id, created_at DESC);
  CREATE INDEX idx_audit_type_time ON audit_logs(event_type, created_at DESC);

  -- 007_create_verification_tokens.up.sql
  CREATE TABLE verification_tokens (
    id          TEXT PRIMARY KEY NOT NULL,
    project_id  TEXT NOT NULL REFERENCES projects(id),
    user_id     TEXT NOT NULL REFERENCES users(id),
    token_hash  BYTEA NOT NULL UNIQUE,
    type        TEXT NOT NULL CHECK (type IN ('email_verify', 'password_reset', 'magic_link')),
    used        BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
  );
  CREATE INDEX idx_vt_hash ON verification_tokens(token_hash) WHERE used = false;

  -- 008_create_encryption_keys.up.sql
  CREATE TABLE encryption_keys (
    id              TEXT PRIMARY KEY NOT NULL,
    project_id      TEXT REFERENCES projects(id),   -- NULL = global key
    user_id         TEXT REFERENCES users(id),       -- NULL = project-level key
    encrypted_key   BYTEA NOT NULL,                  -- DEK encrypted by KEK (pepper)
    key_type        TEXT NOT NULL CHECK (key_type IN ('project_dek', 'user_dek')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ                      -- GDPR erasure: revoke user DEK
  );
  CREATE INDEX idx_ek_project ON encryption_keys(project_id) WHERE revoked_at IS NULL;
  CREATE INDEX idx_ek_user ON encryption_keys(user_id) WHERE revoked_at IS NULL;

  -- 009_create_admin_users.up.sql
  CREATE TABLE admin_users (
    id            TEXT PRIMARY KEY NOT NULL,    -- Go'da UUIDv7 ile uretilir
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'developer')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
  );

  -- 010_create_password_history.up.sql
  CREATE TABLE password_history (
    id          TEXT PRIMARY KEY NOT NULL,
    user_id     TEXT NOT NULL REFERENCES users(id),
    hash        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
  );

  -- 011_create_user_consents.up.sql (GDPR Art. 6/7 — Day 1 tablo, CRUD endpoint Faz 3)
  CREATE TABLE user_consents (
    id          TEXT PRIMARY KEY NOT NULL,
    user_id     TEXT NOT NULL REFERENCES users(id),
    project_id  TEXT NOT NULL REFERENCES projects(id),
    purpose     TEXT NOT NULL,
    granted     BOOLEAN NOT NULL,
    version     TEXT,
    ip          TEXT,
    user_agent  TEXT,
    granted_at  TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  CREATE INDEX idx_consent_user ON user_consents(user_id);
  ```
- sqlc config + generated queries (`internal/database/queries/`)
- ID uretimi Go tarafinda: `google/uuid` ile UUIDv7, prefix eklenerek (`prj_`, `usr_`, `sess_`, vb.)
  ```go
  // internal/id/id.go
  func New(prefix string) string {
    return prefix + uuid.Must(uuid.NewV7()).String()
  }
  // New("prj_") → "prj_0192f5e0-7c1a-7b3e-8d4f-1a2b3c4d5e6f"
  ```

**Kabul kriterleri:**
- [ ] `make migrate` basarili — tum tablolar olusur
- [ ] `make migrate-down` basarili — rollback calisir
- [ ] sqlc ile type-safe query'ler generate edilir
- [ ] Connection pool dogru calisiyor (health check DB'yi kontrol eder)

**Bagimlilk:** T0.1

---

## T0.4 — Redis Connection + Rate Limiter

**Ne:** Redis baglantisi, sliding window rate limiter.

**Yapilacaklar:**
- `internal/redis/client.go` — go-redis v9 connection (pool, sentinel/cluster opsiyonel)
- `internal/ratelimit/limiter.go` — `go-chi/httprate` + `httprate-redis` (Chi-native sliding window, distributed)
- Rate limiter Chi middleware olarak eklenir — ayri middleware yazmaya gerek yok
- Rate limit config:
  ```
  POST /auth/signup    → 5 per 15min per IP
  POST /auth/login     → 10 per 5min per IP, 5 per 5min per account
  POST /auth/password/* → 3 per 15min per account
  GET  /auth/token/refresh → 30 per 1min per session
  # /auth/otp/* → Faz 1'de eklenecek (5 per 5min per account)
  ```
- Response headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `Retry-After`
- 429 response format: `{ "error": "rate_limit_exceeded", "retry_after": 300 }`

**Kabul kriterleri:**
- [ ] Rate limit dogru calisiyor (limit asildiginda 429 doner)
- [ ] httprate-redis distributed — multi-instance'da dogru calisiyor
- [ ] Rate limit header'lari tum response'larda
- [ ] Per-IP + per-account ayri limitler
- [ ] Redis baglantisi kesilirse → log + request'i gec (fail open — rate limit icin)

**Bagimlilk:** T0.1

---

## T0.5 — Crypto Layer (Encryption + Hashing)

**Ne:** Password hashing (Argon2id + pepper), envelope encryption (AES-256-GCM), secure random.

**Yapilacaklar:**
- `internal/crypto/password.go`:
  - `alexedwards/argon2id` wrapper kullanilir (secure defaults, PHC string format, salt handling built-in)
  - `Hash(password string) (string, error)` — HMAC-SHA256(pepper, password) → argon2id.CreateHash()
  - `Verify(password, hash string) (bool, error)` — argon2id.ComparePasswordAndHash() (constant-time)
  - `CheckBreached(password string) (bool, error)` — HaveIBeenPwned k-Anonymity API
  - Params: argon2id.DefaultParams override: m=65536 (64MB), t=3, p=1
  - Pepper: `PALAUTH_PEPPER` env var (zorunlu), ileride KMS
- `internal/crypto/encrypt.go`:
  - `Encrypt(plaintext []byte, key []byte) ([]byte, error)` — AES-256-GCM
  - `Decrypt(ciphertext []byte, key []byte) ([]byte, error)`
  - Per-project DEK uretimi + saklama
  - Per-user DEK (audit log PII icin)
- `internal/crypto/random.go`:
  - `GenerateToken(length int) string` — crypto/rand, hex encoded
  - `GenerateOTP(digits int) string` — 6 haneli numeric

**Kabul kriterleri:**
- [ ] Password hash ~300ms surer (benchmark test)
- [ ] Ayni password iki kez hash'lenince farkli sonuc (salt uniqueness)
- [ ] Constant-time verify: timing variance < 1ms (test ile dogrulanir)
- [ ] HIBP API calisiyor (breached password tespit ediliyor)
- [ ] Encryption/decryption roundtrip basarili
- [ ] Son 4 password hash'i saklanir, tekrar kullanim reddedilir

**Bagimlilk:** T0.1

---

## T0.6 — Project Management + API Key + Admin Auth

**Ne:** Project CRUD, API key uretimi/dogrulama, ve dashboard admin authentication.

**Yapilacaklar:**
- `internal/project/service.go`:
  - `Create(name string, config ProjectConfig) (*Project, *APIKeys, error)`
  - `Get(id string) (*Project, error)`
  - `Update(id string, config ProjectConfig) error`
  - `Delete(id string) error`
  - `List() ([]Project, error)`
- `internal/apikey/service.go`:
  - `Generate(projectID, keyType string) (plainKey string, err error)` — key uretir, hash'ini DB'ye yazar
  - `Verify(key string) (*APIKeyInfo, error)` — hash lookup, project_id doner
  - `Rotate(keyID string) (newPlainKey string, err error)` — yeni key uret, eskiyi grace period sonra sil
  - `Revoke(keyID string) error`
- `internal/apikey/middleware.go`:
  - `X-API-Key` header'dan key okur → project_id context'e ekler
  - Public key (`pk_*`) → public endpoint'ler
  - Secret key (`sk_*`) → admin endpoint'ler
- Key format: `pk_test_` + 32 char random, `sk_live_` + 32 char random
- `internal/admin/auth.go` — Dashboard admin authentication:
  - Admin user'lar ayri tablo: `admin_users` (email, password_hash, role)
  - `POST /admin/login` → admin email+password → admin JWT (ayri signing key)
  - Dashboard bu admin JWT ile Admin API'ye istek atar
  - Admin JWT'de `role: "owner" | "admin" | "developer"` claim'i
  - Setup wizard `/admin/setup` endpoint'i ile ilk admin olusturulur (sadece admin_users tablosu bossa calisir)

**Endpoint'ler:**
```
POST   /admin/setup                 → { email, password } → Ilk admin + default project olustur (sadece admin_users bossa calisir)
POST   /admin/login                 → { email, password } → { admin_token } (admin JWT)
POST   /admin/projects              → Yeni project olustur (API key'ler ile birlikte doner)
GET    /admin/projects              → Project listesi
GET    /admin/projects/:id          → Project detay
PUT    /admin/projects/:id/config   → Config guncelle
DELETE /admin/projects/:id          → Project sil
POST   /admin/projects/:id/keys/rotate → API key rotate
GET    /admin/projects/:id/keys     → API key listesi (hash'siz, prefix + metadata)
```

**Kabul kriterleri:**
- [ ] `/admin/setup` ilk admin + project olusturuyor (sadece bir kez calisir)
- [ ] `/admin/setup` zaten admin varsa 409 doner
- [ ] `/admin/login` dogru credentials → admin JWT doner
- [ ] Admin JWT ile admin endpoint'lere erisim calisiyor
- [ ] Admin JWT olmadan admin endpoint → 401
- [ ] Project olusturulunca 4 API key uretilir (pk_test, sk_test, pk_live, sk_live)
- [ ] API key ile authenticate edilebiliyor (public endpoint'ler)
- [ ] Yanlis key → 401
- [ ] Revoke edilmis key → 401
- [ ] Key rotation calisiyor (yeni key calisir, eski hala 30sn grace period boyunca gecerli)
- [ ] Tum project endpoint'ler project_id ile scope'lanmis

**Bagimlilk:** T0.3 (DB), T0.5 (crypto), T0.2 (router)

---

## T0.7 — Auth: Signup + Email Verification

**Ne:** Email + password ile kullanici kaydi ve email dogrulama.

**Yapilacaklar:**
- `internal/auth/signup.go`:
  - Password policy kontrolu (15 char min single-factor, 8 char min MFA aktifken [Faz 1+], max 64 char — truncate YASAK, composition yok, HIBP check)
  - Password hash (Argon2id + pepper)
  - Email encryption (AES-256-GCM, per-project DEK)
  - Email hash (deterministic, lookup icin)
  - User DB kaydı
  - **Verification link**: Token uret (256-bit, SHA-256 hash DB'de), **24 saat expiry**. Email'deki link ile dogrulama
  - **VEYA Verification OTP**: 6-haneli kod uret, **5dk expiry** (PSD2 RTS). Email'deki kodu girerek dogrulama
  - Project config ile secilir: `email_verification_method: "link" | "otp"`. Bunlar AYRI mekanizmalar, ayni token degil. Link = uzun omurlu (24h), OTP = kisa omurlu (5dk)
  - JWT + refresh token issue
  - Audit log yaz
- `internal/auth/verify_email.go`:
  - Token dogrulama (hash compare, expiry check, single-use)
  - `email_verified = true` guncelle
  - Audit log yaz

**Endpoint'ler:**
```
POST /auth/signup           → { email, password } → { access_token, refresh_token, user }
POST /auth/verify-email     → { token } → { success }
POST /auth/resend-verification → { email } → { success } (rate limited)
```

**Kabul kriterleri:**
- [ ] Signup basarili — user olusur, token'lar doner
- [ ] Zayif sifre reddedilir (14 char → hata)
- [ ] Breached sifre reddedilir (HIBP)
- [ ] Ayni email ile tekrar signup → hata (ama user enumeration yok — ayni hata mesaji)
- [ ] Email verification token calisiyor
- [ ] Kullanilmis token → hata
- [ ] Suresi dolmus token → hata
- [ ] Audit log yazildi

**Bagimlilk:** T0.5 (crypto), T0.6 (project/apikey), T0.3 (DB), T0.8 (token), T0.11 (audit)

---

## T0.8 — Token Service (JWT + Refresh)

**Ne:** JWT access token issuance, opaque refresh token, rotation, family-based revocation.

**Yapilacaklar:**
- `internal/token/jwt.go`:
  - `Issue(user, session, project) (string, error)` — JWT sign (PS256 veya ES256)
  - `Verify(token string) (*Claims, error)` — signature + expiry + claims validation
  - Claims: sub, iss, aud, exp, iat, jti, kid, acr, amr, auth_time, project_id, custom_claims
  - go-jose/v4 kullan
- `internal/token/refresh.go`:
  - `Issue(userID, sessionID string) (plainToken string, error)` — 256-bit random, hash DB'de
  - `Rotate(oldToken string) (newAccessToken, newRefreshToken string, error)`:
    1. Old token hash'ini bul
    2. Eger `used = true` → STOLEN TOKEN: tum family'yi revoke et, hata don
    3. Eger 30sn grace period icinde ve zaten rotated → onceki rotasyonun sonucunu don
    4. `used = true` yap, yeni token uret (ayni family_id, parent_id = old), yeni JWT issue
  - `RevokeFamily(familyID string) error`
- `internal/token/jwks.go`:
  - `GET /.well-known/jwks.json` → public key'ler
  - Key rotation icin birden fazla key listelenebilir
- `internal/token/custom.go`:
  - `CreateCustomToken(userID string, claims map[string]any, expiresIn time.Duration) (string, error)`:
    1. Admin-only endpoint (sk_live key gerekli)
    2. Ozel JWT uret (user claims + custom claims, configurable expiry, max 1 saat)
    3. Client bu token'i `POST /auth/token/exchange` ile access + refresh token'a cevirir
  - `ExchangeCustomToken(customToken string) (accessToken, refreshToken string, error)`:
    1. Custom token dogrula (signature, expiry)
    2. **Single-use kontrolu**: Token'in `jti` claim'ini Redis'te kontrol et. Daha once kullanildiysa → reject. Kullanildiysa `jti`'yi Redis'te sakla (TTL = token expiry)
    3. User'i bul, session olustur, normal token'lar ver
- `internal/token/introspect.go`:
  - `POST /oauth/introspect` → RFC 7662. Opaque token gecerli mi? Client auth zorunlu
  - Response: `{ "active": true/false, "sub", "scope", "exp", "project_id" }`
- `internal/token/revoke.go`:
  - `POST /oauth/revoke` → RFC 7009. Token iptal
  - Refresh revoke → iliskili access token'lar da gecersiz
  - Her zaman 200 doner (bilgi sizintisi onleme)

**Endpoint'ler:**
```
POST /auth/token/refresh    → { refresh_token } → { access_token, refresh_token }
POST /auth/token/custom     → (admin) { user_id, claims?, expires_in? } → { custom_token }
POST /auth/token/exchange   → { custom_token } → { access_token, refresh_token }
POST /oauth/introspect      → { token, token_type_hint } → { active, sub, scope, ... }
POST /oauth/revoke          → { token, token_type_hint } → 200 (her zaman)
GET  /.well-known/jwks.json → { keys: [...] }
```

**Kabul kriterleri:**
- [ ] JWT dogru imzalaniyor (PS256 veya ES256)
- [ ] JWT dogrulamasi calisiyor (valid token → claims, expired → hata)
- [ ] Refresh token rotation calisiyor (yeni token doner, eski gecersiz)
- [ ] Family-based revocation: eski token reuse → tum family revoke
- [ ] 30sn grace period: concurrent request'ler → ikisi de basarili
- [ ] JWKS endpoint dogru formatta doner
- [ ] kid header dogru set ediliyor
- [ ] JWT'de `auth_time` claim'i var (RFC 9068 zorunlu)
- [ ] Custom token uretimi calisiyor (admin endpoint)
- [ ] Custom token exchange calisiyor (custom token → access + refresh)
- [ ] Token introspection calisiyor (gecerli token → active:true, gecersiz → active:false)
- [ ] Token revocation calisiyor (revoke sonrasi introspect → active:false)
- [ ] Revocation her zaman 200 doner (gecersiz token icin de)

**Bagimlilk:** T0.3 (DB), T0.5 (crypto), T0.2 (router)

---

## T0.9 — Auth: Login + Lockout

**Ne:** Email + password login, brute force protection, user enumeration prevention.

**Yapilacaklar:**
- `internal/auth/login.go`:
  - Email hash ile user lookup (constant-time — user yoksa bile ayni sure)
  - Password verify (Argon2id, constant-time)
  - Lockout check: 10 basarisiz → 30dk lockout
  - Session olustur (`acr = "aal1"`, `amr = ["pwd"]`)
  - `user.last_login_at = now()` guncelle (PCI DSS Req 8.2.6 inaktif 90 gun kontrolu icin)
  - JWT + refresh token issue (`auth_time` claim dahil)
  - Audit log yaz (basarili: `auth.login.success` + `auth_method = "password"`, basarisiz: `auth.login.failure`)
- `internal/auth/lockout.go`:
  - Redis counter: `lockout:{project_id}:{user_id}` → failed count
  - 10 failed → lockout timestamp set
  - Lockout suresi: 30dk (configurable per project)
  - **Not**: Password login lockout = 10 basarisiz (PCI DSS Req 8.3.4). MFA lockout = 5 basarisiz (PSD2 RTS). Farkli threshold'lar KASITLI — MFA daha hassas cunku saldirgan zaten password'u biliyordur

**Endpoint'ler:**
```
POST /auth/login → { email, password } → { access_token, refresh_token, user }
```

**Kabul kriterleri:**
- [ ] Dogru credentials → token'lar doner
- [ ] Yanlis password → 401 `{ "error": "invalid_credentials" }`
- [ ] Var olmayan email → 401 `{ "error": "invalid_credentials" }` (AYNI mesaj, AYNI sure)
- [ ] 10 basarisiz → 429 `{ "error": "account_locked", "retry_after": 1800 }`
- [ ] Lockout suresi dolunca login tekrar calisiyor
- [ ] Basarili login failed counter'i resetliyor
- [ ] Timing attack testi: existing vs non-existing user response time farki < %20

**Bagimlilk:** T0.7 (signup — user var olmali), T0.8 (token), T0.4 (rate limit + Redis)

---

## T0.10 — Auth: Password Reset + Change

**Ne:** Sifremi unuttum akisi ve authenticated sifre degistirme.

**Yapilacaklar:**
- `internal/auth/password_reset.go`:
  - `RequestReset(email)`: Token uret (256-bit), hash'ini DB'ye yaz, **15dk expiry** (spec Section 42 ile uyumlu), email gonder
  - `ConfirmReset(token, newPassword)`: Token dogrula, password policy + son 4 history check, re-hash, tum session'lari revoke et
- `internal/auth/password_change.go`:
  - `Change(userID, currentPassword, newPassword)`: Current verify, policy check, history check, re-hash

**Endpoint'ler:**
```
POST /auth/password/reset         → { email } → { success } (her zaman 200 — enumeration yok)
POST /auth/password/reset/confirm → { token, new_password } → { success }
POST /auth/password/change        → { current_password, new_password } → { success } (authenticated)
```

**Kabul kriterleri:**
- [ ] Reset email gonderiliyor (veya log'a yaziliyor — dev modunda)
- [ ] Token dogru calisir (gecerli token → sifre degisir)
- [ ] Expired token → hata
- [ ] Kullanilmis token → hata
- [ ] Son 4 sifre tekrar kullanilamaz
- [ ] Zayif yeni sifre reddedilir
- [ ] Reset sonrasi tum session'lar sonlandiriliyor
- [ ] Var olmayan email icin de 200 doner (enumeration koruması)

**Bagimlilk:** T0.7 (user), T0.5 (crypto), T0.12 (email)

---

## T0.11 — Audit Log (Tamper-Evident)

**Ne:** SHA-256 hash chain ile tamper-evident audit logging.

**Yapilacaklar:**
- `internal/audit/service.go`:
  - `Log(event AuditEvent) error`:
    1. PII alanlarini per-user DEK ile sifrele
    2. Onceki event'in hash'ini al
    3. `event_hash = SHA256(prev_hash + canonical(event_data))` hesapla (ciphertext uzerinden!)
    4. DB'ye yaz
  - `Verify(projectID string) (*IntegrityReport, error)`:
    1. Tum event'leri sirali oku
    2. Her event icin hash'i yeniden hesapla
    3. Kirik chain varsa raporla
- `internal/audit/types.go` — Event tipleri:
  - `auth.signup`, `auth.login.success`, `auth.login.failure`
  - `auth.logout`
  - `auth.password.reset.request`, `auth.password.reset.complete`
  - `auth.password.change`
  - `auth.email.verify`
  - `session.create`, `session.revoke`
  - `token.issue`, `token.refresh`, `token.revoke`
  - `admin.user.create`, `admin.user.update`, `admin.user.delete`
  - `admin.config.change`
  - `admin.key.rotate`
  - **`gdpr.erasure`** — Kullanici silme + DEK revoke (spec Section 16.3 zorunlu)
- `internal/audit/event.go` — Audit event struct (spec Section 16.2 formati):
  ```go
  type AuditEvent struct {
    EventID    string          // UUIDv7
    TraceID    string          // Request correlation ID (middleware'den)
    EventType  string
    Actor      ActorInfo       // PII — encrypt edilecek
    Target     TargetInfo      // resource type + id
    Result     string          // "success" | "failure"
    AuthMethod string          // "password", "password+totp", vb.
    RiskScore  float64         // 0.0-1.0 (Faz 0'da her zaman 0.0, Faz 2'de risk engine)
    ProjectID  string
    Metadata   map[string]any  // ek bilgiler — encrypt edilecek
  }
  ```
- `internal/audit/canonical.go` — Deterministic JSON serialization (key'ler sorted)

**Endpoint'ler:**
```
GET  /admin/projects/:id/audit-logs         → { logs: [...], pagination }
POST /admin/projects/:id/audit-logs/verify  → { valid: true/false, broken_at: "..." }
GET  /admin/projects/:id/audit-logs/export  → JSON/CSV download
```

**Kabul kriterleri:**
- [ ] Her auth event loglanir
- [ ] Hash chain tutarli — verify basarili
- [ ] DB'de bir log degistirilirse verify basarisiz olur + kirik noktayi raporlar
- [ ] PII alanlari sifreli saklanir
- [ ] Canonical JSON deterministic (ayni data → ayni hash, her zaman)
- [ ] `gdpr.erasure` event tipi loglanir (user delete'te)
- [ ] Erasure sonrasi: PII okunamaz ama hash chain hala gecerli
- [ ] Pagination calisiyor (cursor-based)
- [ ] Export calisiyor (JSON + CSV)

**Bagimlilk:** T0.3 (DB), T0.5 (crypto)

---

## T0.12 — Email Service (Pluggable)

**Ne:** Pluggable email gonderim (SMTP, SES, SendGrid). Dev modunda console log.

**Yapilacaklar:**
- `internal/email/service.go` — Interface:
  ```go
  type EmailSender interface {
    Send(ctx context.Context, to, subject, htmlBody, textBody string) error
  }
  ```
- `internal/email/smtp.go` — SMTP implementation
- `internal/email/console.go` — Dev modu: email'i console'a yazdir (gercekten gonderme)
- `internal/email/templates/` — Go template'ler:
  - `verification.html` — Email dogrulama
  - `password_reset.html` — Sifre sifirlama
  - `welcome.html` — Hosgeldin
- Template'ler project branding'ini destekler (logo, renk — config'den)
- XSS koruması: Template degiskenleri otomatik escape

**Kabul kriterleri:**
- [ ] SMTP ile email gonderiliyor (test SMTP server — MailHog)
- [ ] Dev modunda console'a yaziliyor (`EMAIL_PROVIDER=console`)
- [ ] Template'ler dogru render ediliyor
- [ ] XSS: Template'e `<script>` inject edilemiyor
- [ ] Plaintext fallback her email'de var

**Bagimlilk:** T0.1

---

## T0.13 — Session Management

**Ne:** Session CRUD, timeout enforcement, aktif session listesi, remote revocation.

**Yapilacaklar:**
- `internal/session/service.go`:
  - `Create(userID, projectID, deviceInfo) (*Session, error)` — session olustur, timeout'lari set et
  - `Get(sessionID string) (*Session, error)` — timeout kontrol, expired ise revoke
  - `List(userID string) ([]Session, error)` — aktif session'lar (device info ile)
  - `Revoke(sessionID string) error` — tek session kapat
  - `RevokeAll(userID string) error` — tum session'lari kapat
  - `Touch(sessionID string) error` — idle timeout'u resetle (last_activity guncelle)
- Session timeout AAL-based (NIST 800-63B-4 Rev 4):
  ```
  AAL1: idle = yok,     absolute = 30 gun (SHOULD)
  AAL2: idle = 1 saat (SHOULD), absolute = 24 saat (SHOULD)
  AAL3: idle = 15dk (SHOULD),   absolute = 12 saat (SHALL)
  ```
  Session create edilirken `acr` degerine gore timeout set edilir.
  Project config ile override edilebilir (ama NIST SHALL altina inilemez).
- `acr` ve `amr` session create'te set edilir:
  - Faz 0'da sadece email+password: `acr = "aal1"`, `amr = ["pwd"]`
  - Faz 1'de MFA eklenince: `acr = "aal2"`, `amr = ["pwd", "otp"]`
- Session middleware: Her authenticated request'te `Touch()` cagir, expired ise 401

**Endpoint'ler:**
```
GET    /auth/sessions          → { sessions: [...] } (authenticated user'in session'lari)
DELETE /auth/sessions/:id      → session sonlandir
DELETE /auth/sessions          → tum session'lari sonlandir (logout all devices)
POST   /auth/logout            → mevcut session'i sonlandir
```

**Kabul kriterleri:**
- [ ] Session olusturuluyor (login basarili)
- [ ] AAL1 session: idle timeout yok, absolute 30 gun
- [ ] AAL2 session: idle 1 saat, absolute 24 saat
- [ ] AAL3 session: idle 15dk, absolute 12 saat
- [ ] Touch calisiyor — her request idle timer'i resetliyor
- [ ] Session'da `acr` ve `amr` dogru set ediliyor (Faz 0: acr=aal1, amr=["pwd"])
- [ ] Session listesi dogru (cihaz, IP, son aktivite gorunuyor)
- [ ] Tek session revoke calisiyor
- [ ] Tum session'lar revoke calisiyor (logout all)
- [ ] Revoked session ile request → 401

**Bagimlilk:** T0.3 (DB), T0.8 (token — session_id JWT'de)

---

## T0.14 — Admin User CRUD

**Ne:** Admin API ile kullanici yonetimi.

**Yapilacaklar:**
- `internal/admin/users.go`:
  - `CreateUser(projectID, email, password, metadata)` — admin tarafindan user olusturma
  - `GetUser(projectID, userID)` — detay (profil, session'lar, MFA durumu)
  - `UpdateUser(projectID, userID, fields)` — metadata, email_verified, banned, custom_claims
  - `DeleteUser(projectID, userID)` — GDPR erasure (user sil + audit log'da cryptographic erasure)
  - `ListUsers(projectID, filters, pagination)` — arama, filtreleme, cursor pagination
  - `BanUser(projectID, userID, reason)` — ban + tum session revoke
  - `UnbanUser(projectID, userID)`
- Tum islemler audit log'a yazilir (`admin.user.*` event'leri)
- **GDPR erasure akisi (T0.14 + T0.11 + T0.5):**
  1. User record soft-delete
  2. User'in encryption DEK'ini revoke et (`encryption_keys.revoked_at = now()`)
  3. `gdpr.erasure` audit event logla (spec Section 16.3 zorunlu)
  4. Audit log'daki PII artik deşifre edilemez — chain bozulmaz
- **Inaktif hesap kontrolu (PCI DSS v4.0.1 Req 8.2.6):**
  - Background job: 90 gundur login olmayan hesaplari `banned = true` + `ban_reason = 'inactive_90d'` yap
  - Cron: Gunluk calisir
  - Audit log: `admin.user.deactivate_inactive` event'i

**Endpoint'ler:**
```
POST   /admin/projects/:id/users          → { email, password?, metadata }
GET    /admin/projects/:id/users          → { users: [...], cursor }
GET    /admin/projects/:id/users/:uid     → { user }
PUT    /admin/projects/:id/users/:uid     → { metadata?, banned?, custom_claims? }
DELETE /admin/projects/:id/users/:uid     → GDPR erasure (DEK revoke + erasure event)
POST   /admin/projects/:id/users/:uid/ban → { reason }
POST   /admin/projects/:id/users/:uid/unban
POST   /admin/projects/:id/users/:uid/reset-password → admin tarafindan password reset tetikle (email gonder veya gecici sifre uret). Tum session'lar sonlandirilir. Audit log yazilir. (spec Section 11.1.4)
GET    /admin/projects/:id/analytics      → { mau, login_trend_24h, active_sessions }
POST   /admin/users/invite                → { email, role } → admin kullanici davet
```

**Kabul kriterleri:**
- [ ] Admin user olusturabiliyor
- [ ] Filtreleme calisiyor (email arama, banned filtre)
- [ ] Pagination calisiyor (cursor-based)
- [ ] Ban calisiyor — banned user login olamiyor
- [ ] Delete calisiyor — user siliniyor + DEK revoke + `gdpr.erasure` audit event + PII okunamiyor
- [ ] Audit log hash chain delete sonrasi hala gecerli (ciphertext degismedi)
- [ ] Inaktif hesap 90 gun kontrolu calisiyor (cron job)
- [ ] Analytics endpoint calisiyor (MAU, login trendi)
- [ ] Admin davet calisiyor (email + rol)
- [ ] Admin password reset calisiyor → email gonderilir + tum session'lar sonlanir
- [ ] Tum islemler audit logda

**Bagimlilk:** T0.7 (user), T0.11 (audit), T0.6 (apikey — admin auth)

---

## T0.15 — OpenAPI Spec + SDK Generation Altyapisi

**Ne:** OpenAPI spec yazimi, SDK generation pipeline kurulumu.

**Yapilacaklar:**
- `api/openapi.yaml` — Tum Faz 0 endpoint'lerini tanimla
- oapi-codegen config: Go server types + Chi router integration
- SDK generation script:
  - TypeScript client SDK: `npx @openapitools/openapi-generator-cli generate -g typescript-fetch`
  - TypeScript server SDK: Admin endpoint'ler icin ayri
  - Go SDK: Types + client
- `sdk/typescript/client/` — Generated + thin wrapper (createAuthClient, onAuthStateChange, auto-refresh)
- `sdk/typescript/server/` — Generated + thin wrapper (createAuthServer, hooks, events)
- `sdk/go/` — Generated Go client
- npm package config: `@palauth/client`, `@palauth/server`

**Kabul kriterleri:**
- [ ] OpenAPI spec valid (swagger-cli validate)
- [ ] Go types generate ediliyor
- [ ] TypeScript SDK generate ediliyor
- [ ] `createAuthClient({ url, apiKey })` calisiyor
- [ ] `auth.signUp()`, `auth.signIn()` calisiyor (Go server'a istek atiyor)
- [ ] `createAuthServer({ url, serviceKey })` calisiyor
- [ ] `auth.verifyToken()` calisiyor

**Bagimlilk:** T0.7, T0.8, T0.9, T0.10, T0.13, T0.14 (endpoint'ler mevcut olmali)

---

## T0.16 — Dashboard: Setup + Projects + Users

**Ne:** Next.js dashboard — setup wizard, project listesi, user yonetimi.

**Yapilacaklar:**
- `dashboard/` — Next.js 15 App Router + shadcn/ui + Tailwind + React Query
- Setup wizard (ilk acilis):
  1. Admin email + sifre olustur
  2. Ilk project olustur
  3. API key'leri goster
  4. Quickstart rehberi
- Projects sayfasi: Kart gorunumu, yeni olustur
- Project detail → Overview: MAU, login trendi (basit)
- Project detail → Users: Liste, arama, detay, ban/unban, password reset, delete
- Project detail → API Keys: Goster (gizli default), rotate, kopyala
- Project detail → Settings: Auth config (toggle'lar), session policy, email provider
- Project detail → Audit Logs: Stream, filtre, export, verify integrity
- Global → Admin Users: Dashboard erisim rolleri

**Kabul kriterleri:**
- [ ] `docker compose up` → dashboard localhost:3001'de calisir
- [ ] Setup wizard calisiyor — admin + project + key'ler olusur
- [ ] Project listesi gorunuyor
- [ ] User listesi gorunuyor, arama calisiyor
- [ ] Ban/unban calisiyor
- [ ] API key goruntulenebiliyor, kopyalanabiliyor
- [ ] Audit log stream gorunuyor, filtre calisiyor
- [ ] Verify integrity butonu calisiyor

**Bagimlilk:** T0.6, T0.14 (admin API endpoint'leri mevcut olmali)

---

## T0.17 — Test Suite (Unit + Integration + Security)

**Ne:** Tum Faz 0 ozelliklerini kapsayan test suite.

**Yapilacaklar (spec Section 43 — 12 katman test stratejisi):**

**Katman 1 — Unit tests (Go `testing` + testify):**
- Password hashing (timing, salt uniqueness, HIBP, history)
- Token issuance + verification
- Refresh token rotation + family revocation
- Rate limit counter logic
- Audit log hash chain calculation
- Canonical JSON serialization
- Custom token create + exchange

**Katman 2 — Property-based tests (rapid):**
- Salt uniqueness invariant (ayni password → farkli hash)
- JWT exp > iat invariant
- Token family revocation invariant (reuse → tum family revoked)
- Audit log canonical JSON deterministic invariant

**Katman 3 — AI Security Review:**
- Claude Code Security Review GitHub Action her PR'da calisir (T0.1'de kuruldu)
- `claude /security-review` development sirasinda

**Katman 4 — Integration tests (testcontainers-go):**
- Full signup → login → refresh → logout flow
- Lockout (10 failed → 30dk)
- Token rotation + family revocation in DB
- Session timeout enforcement (AAL1/AAL2/AAL3 farkli timeout'lar)
- GDPR erasure (delete user → audit log chain intact)
- Custom token exchange flow
- Admin setup → login → CRUD

**Katman 5 — Contract tests:**
- Faz 0'da SDK yok → Pact testi yok. Faz 5'te (SDK fazinda) eklenir

**Katman 6 — DAST (OWASP ZAP):**
- ZAP Docker image baseline scan: Tum auth endpoint'lerine karsi
- CI/CD: Her PR'da baseline (pasif), aylik active scan
- Auth endpoint'ler: `/auth/signup`, `/auth/login`, `/auth/password/*`, `/admin/*`

**Katman 7 — E2E tests (Playwright):**
- Dashboard setup wizard: Admin olustur → project olustur → API key goster
- Dashboard user management: Liste → detay → ban → unban
- Dashboard audit log: Stream → filtre → verify integrity

**Katman 8 — Mutation testing (gremlins):**
- Guvenlik-kritik modullerde: `internal/crypto/*`, `internal/token/*`, `internal/auth/*`, `internal/audit/*`
- Hedef: %80+ mutation score (guvenlik modulleri)
- Surviving mutant'lar = eksik test = potential security bug

**Katman 9 — API Fuzzing:**
- Go native fuzzing: Login, signup, password reset endpoint input fuzzing
- RESTler (haftalik CI cron): OpenAPI spec'ten stateful API fuzzing

**Katman 10 — Chaos testing (Toxiproxy):**
- Redis coktu → rate limiter ne yapiyor? (fail-open olmali)
- DB connection pool doldu → login calisiyor mu?
- Hook endpoint timeout → deny_on_failure calisiyor mu? (Faz 1'de hook eklenince)
- Network latency 500ms → session performance

**Katman 11 — Load tests (k6):**
- Login endpoint: 1000 concurrent user, p99 < 500ms
- Token refresh: p99 < 100ms
- Rate limiter baskisi altinda dogru calisiyor mu
- Signup: 100 concurrent registration

**Katman 12 — Conformance tests:**
- Faz 0'da OIDC/FIDO2 yok → conformance testi yok. Faz 2+'de eklenir

**CI/CD tetikleme (spec Section 43.3):**
| Tetikleme | Calisanlar |
|-----------|------------|
| Her `git push` | Unit + property-based + lint |
| Her PR | + AI Security Review + integration + DAST baseline |
| PR merge to main | + E2E + mutation (security modulleri) |
| Haftalik (CI cron) | + Full mutation + RESTler fuzzing + k6 load |
| Aylik | + Chaos testing (Toxiproxy) + full DAST active scan |

**Kabul kriterleri:**
- [ ] `make test` tum testler gecer
- [ ] Coverage: %85+ (guvenlik modulleri %90+)
- [ ] Property-based testler 10,000 input ile gecerli
- [ ] Integration testler gercek DB + Redis ile calisir (testcontainers)
- [ ] Go native fuzz testler crash uretmiyor
- [ ] DAST baseline scan: critical/high finding yok
- [ ] Mutation score: guvenlik modulleri %80+
- [ ] k6 load test: login p99 < 500ms (1000 concurrent)
- [ ] Chaos test: Redis down → rate limit fail-open, login calisiyor
- [ ] E2E: Dashboard setup + user management Playwright ile calisiyor
- [ ] CI/CD pipeline tum tetiklemelerde otomatik calisir

**Bagimlilk:** T0.1-T0.16 (tum Faz 0 tamamlanmis olmali)

---

## T0.18 — Docker + Docker Compose

**Ne:** Production-ready Docker image'lar ve docker-compose.

**Yapilacaklar:**
- `docker/Dockerfile.server`:
  ```dockerfile
  FROM golang:1.26-alpine AS builder
  WORKDIR /app
  COPY go.* ./
  RUN go mod download
  COPY . .
  RUN CGO_ENABLED=0 go build -o palauth ./cmd/server

  FROM scratch
  COPY --from=builder /app/palauth /palauth
  COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
  EXPOSE 3000
  ENTRYPOINT ["/palauth", "serve"]
  ```
- `docker/Dockerfile.dashboard` — Next.js multi-stage
- `docker/docker-compose.prod.yml` (production — T0.1'deki dev compose'dan FARKLI):
  ```yaml
  services:
    palauth:
      build: { context: .., dockerfile: docker/Dockerfile.server }
      ports: ["3000:3000"]
      environment:
        DATABASE_URL: postgres://palauth:palauth@postgres:5432/palauth?sslmode=disable
        REDIS_URL: redis://redis:6379
        PALAUTH_PEPPER: ${PALAUTH_PEPPER}
        EMAIL_PROVIDER: console
      depends_on: [postgres, redis]
    dashboard:
      build: { context: ../dashboard, dockerfile: Dockerfile }
      ports: ["3001:3000"]
      environment:
        PALAUTH_URL: http://palauth:3000
    postgres:
      image: postgres:16-alpine
      environment: { POSTGRES_DB: palauth, POSTGRES_USER: palauth, POSTGRES_PASSWORD: palauth }
      volumes: [pgdata:/var/lib/postgresql/data]
    redis:
      image: redis:7-alpine
  volumes:
    pgdata:
  ```
- `docker/docker-compose.dev.yml` — Hot reload (air) + debug
- `.env.example` — Gerekli env var'lar

**Kabul kriterleri:**
- [ ] `docker compose up` → her sey ayaga kalkiyor
- [ ] Go image ~15MB (scratch base)
- [ ] Health check'ler calisiyor
- [ ] Hot reload dev modunda calisiyor
- [ ] `docker compose down && docker compose up` → veri korunuyor (volume)

**Bagimlilk:** T0.1-T0.16

---

## Bagimlilk Grafi

```
T0.1 (scaffold)
  ├── T0.2 (http server)
  ├── T0.3 (database) ──────┐
  ├── T0.4 (redis/ratelimit) │
  ├── T0.5 (crypto)          │
  └── T0.12 (email)          │
                              │
T0.6 (project/apikey) ←──────┤ T0.2 + T0.3 + T0.5
                              │
T0.8 (token) ←────────────────┤ T0.3 + T0.5
                              │
T0.11 (audit) ←───────────────┤ T0.3 + T0.5
                              │
T0.7 (signup) ←───────────────┤ T0.5 + T0.6 + T0.8 + T0.11 + T0.12
                              │
T0.9 (login) ←────────────────┤ T0.7 + T0.8 + T0.4
                              │
T0.10 (password reset) ←──────┤ T0.7 + T0.5 + T0.12
                              │
T0.13 (session) ←─────────────┤ T0.3 + T0.8
                              │
T0.14 (admin CRUD) ←──────────┤ T0.7 + T0.11 + T0.6
                              │
T0.15 (OpenAPI + SDK) ←───────┤ T0.7-T0.14 (tum endpoint'ler)
                              │
T0.16 (dashboard) ←───────────┤ T0.6 + T0.14
                              │
T0.17 (test suite) ←──────────┤ T0.1-T0.16 (her sey)
                              │
T0.18 (docker) ←──────────────┤ T0.1-T0.16 (her sey)
```

## Haftalik Plan (16 hafta)

| Hafta | Task'lar | Not |
|-------|----------|-----|
| 1 | T0.1 (scaffold + dev compose + config) + T0.2 (http + error format) | Temel yapi + dev ortami |
| 2 | T0.3 (db + migrations) + T0.4 (redis + httprate) | Data katmani |
| 3 | T0.5 (crypto — argon2id, AES, random) + T0.11 (audit log) | Guvenlik + audit (audit erken lazim) |
| 4 | T0.12 (email) + T0.6 (project + apikey + admin auth) | Email + project yonetimi |
| 5-6 | T0.8 (token — JWT + refresh + JWKS) | Token sistemi |
| 7-8 | T0.7 (signup) + T0.9 (login + lockout) | Core auth akislari |
| 9 | T0.10 (password reset/change) + T0.13 (session) | Password + session |
| 10-11 | T0.14 (admin CRUD) + T0.16 (dashboard baslangic) | Admin API + dashboard paralel |
| 12-13 | T0.15 (OpenAPI + SDK generate) + T0.16 (dashboard devam) | SDK + dashboard |
| 14-15 | T0.17 (final test sweep — coverage, fuzz, security, integration) | Test sweep |
| 16 | T0.18 (production Docker + Helm) + documentation | Production deployment |

**Not:** Her task kendi testini birlikte yazar (hafta 1'den itibaren). T0.17 "sifirdan test yaz" degil, "final sweep + coverage %85+ dogrula + fuzz + security tests" dir.
