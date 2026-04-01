# PalAuth — Faz 1: MFA + Social Login + Hooks (Ay 5-7)

> Hedef: Firebase/Supabase seviyesi + blocking hooks avantaji. Helm chart ile Kubernetes-ready.
> Faz 0 uzerine insa — hicbir Faz 0 kodu degistirilmez, sadece yeni dosyalar + mevcut dosyalara if/else eklenir.
> Tum paketler zaten Faz 0'da go.mod'a eklenmis: `pquerna/otp`, `skip2/go-qrcode`, `golang.org/x/oauth2`, `watermill`

---

## Yeni DB Migration'lar

```sql
-- 012_create_mfa_enrollments.up.sql
CREATE TABLE mfa_enrollments (
  id              TEXT PRIMARY KEY NOT NULL,
  project_id      TEXT NOT NULL REFERENCES projects(id),
  user_id         TEXT NOT NULL REFERENCES users(id),
  type            TEXT NOT NULL CHECK (type IN ('totp', 'webauthn', 'sms', 'email')),
  secret_encrypted BYTEA,            -- TOTP secret (AES-GCM per-user DEK)
  verified        BOOLEAN NOT NULL DEFAULT false,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_mfa_user ON mfa_enrollments(user_id) WHERE verified = true;

-- 013_create_recovery_codes.up.sql
CREATE TABLE recovery_codes (
  id          TEXT PRIMARY KEY NOT NULL,
  user_id     TEXT NOT NULL REFERENCES users(id),
  code_hash   TEXT NOT NULL,          -- Argon2id hash
  used        BOOLEAN NOT NULL DEFAULT false,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  used_at     TIMESTAMPTZ
);

-- 014_create_identities.up.sql (social login)
CREATE TABLE identities (
  id              TEXT PRIMARY KEY NOT NULL,
  project_id      TEXT NOT NULL REFERENCES projects(id),
  user_id         TEXT NOT NULL REFERENCES users(id),
  provider        TEXT NOT NULL,       -- 'google', 'apple', 'github', 'microsoft'
  provider_user_id TEXT NOT NULL,
  provider_data   JSONB NOT NULL DEFAULT '{}',  -- profile info, tokens
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX idx_identity_provider ON identities(project_id, provider, provider_user_id);
CREATE INDEX idx_identity_user ON identities(user_id);

-- 015_create_hook_configs.up.sql
CREATE TABLE hook_configs (
  id              TEXT PRIMARY KEY NOT NULL,
  project_id      TEXT NOT NULL REFERENCES projects(id),
  event           TEXT NOT NULL,       -- 'before.user.create', 'before.login', 'after.login', vb.
  url             TEXT NOT NULL,
  signing_key_encrypted BYTEA NOT NULL, -- HMAC-SHA256 secret (AES-GCM per-project DEK ile sifreli)
  timeout_ms      INTEGER NOT NULL DEFAULT 15000,
  failure_mode    TEXT NOT NULL DEFAULT 'deny' CHECK (failure_mode IN ('deny', 'allow')),
  enabled         BOOLEAN NOT NULL DEFAULT true,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_hook_project_event ON hook_configs(project_id, event) WHERE enabled = true;

-- 016_create_hook_logs.up.sql
CREATE TABLE hook_logs (
  id              TEXT PRIMARY KEY NOT NULL,
  hook_config_id  TEXT NOT NULL REFERENCES hook_configs(id),
  project_id      TEXT NOT NULL,
  event           TEXT NOT NULL,
  request_body    JSONB,
  response_body   JSONB,
  response_status INTEGER,
  latency_ms      INTEGER NOT NULL,
  result          TEXT NOT NULL CHECK (result IN ('allow', 'deny', 'timeout', 'error')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_hooklog_config ON hook_logs(hook_config_id, created_at DESC);

-- 017_create_webhook_subscriptions.up.sql
CREATE TABLE webhook_subscriptions (
  id          TEXT PRIMARY KEY NOT NULL,
  project_id  TEXT NOT NULL REFERENCES projects(id),
  url         TEXT NOT NULL,
  events      JSONB NOT NULL DEFAULT '[]',   -- ["user.created", "auth.login.success"]
  secret_hash TEXT NOT NULL,
  enabled     BOOLEAN NOT NULL DEFAULT true,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 018_create_webhook_deliveries.up.sql
CREATE TABLE webhook_deliveries (
  id                TEXT PRIMARY KEY NOT NULL,
  subscription_id   TEXT NOT NULL REFERENCES webhook_subscriptions(id),
  event_id          TEXT NOT NULL,
  event_type        TEXT NOT NULL,
  status            TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'success', 'failed', 'dlq')),
  attempts          INTEGER NOT NULL DEFAULT 0,
  last_attempt_at   TIMESTAMPTZ,
  next_retry_at     TIMESTAMPTZ,
  request_body      JSONB,
  response_status   INTEGER,
  response_body     TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_wd_pending ON webhook_deliveries(next_retry_at) WHERE status = 'pending';
CREATE INDEX idx_wd_dlq ON webhook_deliveries(subscription_id) WHERE status = 'dlq';

-- 019_add_users_has_mfa.up.sql
ALTER TABLE users ADD COLUMN has_mfa BOOLEAN NOT NULL DEFAULT false;

-- 020_create_trusted_devices.up.sql (spec Section 5.2)
CREATE TABLE trusted_devices (
  id              TEXT PRIMARY KEY NOT NULL,
  user_id         TEXT NOT NULL REFERENCES users(id),
  project_id      TEXT NOT NULL REFERENCES projects(id),
  token_hash      BYTEA NOT NULL UNIQUE,
  device_fp_hash  TEXT NOT NULL,
  device_name     TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at      TIMESTAMPTZ NOT NULL   -- 30 gun
);
CREATE INDEX idx_td_user ON trusted_devices(user_id) WHERE expires_at > now();
```

---

## T1.1 — TOTP + Email OTP MFA Enrollment + Verification

**Ne:** TOTP (authenticator app) + Email OTP ile MFA. QR code enrollment, 6 haneli dogrulama, backup codes.

**Yapilacaklar:**
- `internal/mfa/totp.go`:
  - `Enroll(userID string) (*TOTPEnrollment, error)`:
    1. `pquerna/otp` ile TOTP secret uret (SHA1, 6 digit, 30sn — RFC 6238)
    2. Secret'i per-user DEK ile AES-256-GCM sifrele → DB'ye yaz (verified=false)
    3. `skip2/go-qrcode` ile QR code uret (otpauth:// URI)
    4. QR code PNG + secret string (manual entry icin) don
  - `Verify(userID, code string) (bool, error)`:
    1. DB'den enrollment al, secret'i decrypt et
    2. `pquerna/otp` ile TOTP dogrula (1-step drift tolerance: ±30sn)
    3. Basarili ise: `verified = true`, `user.has_mfa = true`
    4. Constant-time comparison
  - `Validate(userID, code string) (bool, error)` — login sirasinda MFA challenge dogrulama
    1. Ayni TOTP verify logic
    2. Replay koruması: son kullanilan code + timestamp Redis'te saklanir, tekrar kullanilamaz
    3. Max 5 basarisiz deneme → MFA lockout 30dk (PSD2 RTS + PCI DSS Req 8.3.4 ile uyumlu). Lockout sadece MFA challenge'a uygulanir, kullanicinin password login'i calismaya devam eder (ama MFA tamamlanamadigi icin access token verilmez)
  - MFA token (`mfa_token`): Login basarili + MFA gerekli durumunda uretilir
    - Opaque token, 256-bit random
    - **5dk expiry** (PSD2 RTS max 5dk auth code lifetime)
    - Tek kullanimlik — MFA challenge tamamlaninca veya expire olunca gecersiz
    - Redis'te saklanir (user_id + session bilgisi ile)
- `internal/mfa/email_otp.go` — Email OTP as MFA factor (spec Section 2.2 + Section 3.2):
  - `Challenge(userID)`: 6 haneli OTP uret, email gonder, 5dk expiry (PSD2 RTS)
  - `Verify(userID, code)`: OTP dogrula (constant-time, replay koruması, max 3 basarisiz → yeni OTP gerekli)
  - MFA enrollment olarak eklenebilir (type: "email")
  - TOTP'ye alternatif — kullanici tercih eder

- `internal/mfa/recovery.go`:
  - `GenerateCodes(userID string) ([]string, error)`:
    1. 10 adet 8 karakterlik recovery code uret (crypto/rand, base32)
    2. Her birini Argon2id ile hashle → DB'ye yaz
    3. Plaintext kodlari sadece bu sefer goster (bir daha gosterilemez)
  - `UseCode(userID, code string) (bool, error)`:
    1. Tum unused kodlari cek, her biriyle constant-time compare
    2. Eslesen varsa: `used = true`, `used_at = now()`
    3. MFA yerine gecerli (recovery)
    4. **Tum diger session'lar sonlandirilir** (spec Section 11.2)
    5. **`user.has_mfa = false`** set edilir → kullanici yeni MFA enrollment yapmak ZORUNDA (spec Section 11.2)
    6. `mfa.recovery.used` audit event loglanir

**Faz 0'da degisen kodlar:**
- `internal/auth/login.go` → MFA kontrolu eklenir:
  ```go
  // Mevcut login logic'ten sonra:
  if user.HasMFA {
    return MFARequiredResponse{MFAToken: mfaToken}, nil  // access token DONMEZ
  }
  // MFA yoksa normal devam
  ```
- `internal/admin/auth.go` → Admin login'de MFA zorunlu kontrolu:
  - Admin MFA enrolled degilse → login sonrasi zorla MFA enrollment ekrani
  - Admin MFA enrolled ise → login + MFA challenge (SOC 2 + PCI DSS 8.4.1: admin erisimi MFA zorunlu)
  - Admin JWT sadece MFA tamamlandiktan sonra verilir
- Session create'te: MFA tamamlaninca `acr = "aal2"`, `amr = ["pwd", "otp"]`
  - **Not:** NIST 800-63B-4 AAL2 tam uyumu Faz 2'de tamamlanir (WebAuthn = phishing-resistant secenek sunma zorunlulugu, Sec 2.2.2 SHALL). Faz 1'de TOTP ile MFA calisiyor ve session acr=aal2 set ediliyor ama phishing-resistant secenek henuz yok

**Endpoint'ler:**
```
POST /auth/mfa/enroll       → { type: "totp" } → { secret, qr_code_url, recovery_codes }
POST /auth/mfa/verify       → { code } → { success } (enrollment dogrulama)
POST /auth/mfa/challenge     → { mfa_token, type: "totp", code } → { access_token, refresh_token }
POST /auth/mfa/recovery     → { mfa_token, code } → { access_token, refresh_token }
GET  /auth/mfa/factors      → { factors: [...] } (enrolled MFA methods)
DELETE /auth/mfa/factors/:id → MFA enrollment sil (re-auth gerekli)
POST /auth/mfa/recovery-codes/regenerate → { recovery_codes } (yeni kodlar, eskiler gecersiz)
POST /auth/mfa/email/enroll     → { } → Email OTP enrollment (mevcut verified email kullanilir)
POST /auth/mfa/email/challenge  → { mfa_token } → Email OTP gonder
POST /auth/mfa/email/verify     → { mfa_token, code } → Email OTP dogrula
```

**Audit event'ler:** `mfa.enroll`, `mfa.verify.success`, `mfa.verify.failure`, `mfa.remove`, `mfa.recovery.used`

**Kabul kriterleri:**
- [ ] TOTP enrollment calisiyor — QR code + secret donuyor
- [ ] QR code Google Authenticator/Authy ile taraniyor ve kod uretiliyor
- [ ] Dogru TOTP kodu → MFA verified, session acr=aal2
- [ ] Yanlis kod → 401, 5 basarisiz → MFA lockout
- [ ] Replay koruması: Ayni kod 30sn icinde tekrar kullanilamaz
- [ ] Clock drift ±30sn calisiyor (onceki/sonraki kod kabul)
- [ ] Recovery codes: 10 adet uretiliyor, kullanilinca tekrar kullanilamaz
- [ ] Recovery code ile MFA bypass calisiyor (acil durum)
- [ ] Recovery code kullanildiginda tum diger session'lar sonlandirilir (spec Section 11.2)
- [ ] Recovery code kullanildiginda yeni MFA enrollment zorunlu (spec Section 11.2)
- [ ] Login flow: has_mfa=true → mfa_required donuyor, access token donmuyor
- [ ] MFA token 5dk sonra expire oluyor (PSD2 RTS max 5dk)
- [ ] MFA challenge → basarili → access token + refresh token donuyor
- [ ] TOTP secret AES-GCM ile sifreli saklanir
- [ ] Email OTP: 6 haneli, 5dk expiry, replay koruması calisiyor
- [ ] Email OTP: 3 basarisiz → yeni OTP gerekli
- [ ] Email OTP: MFA challenge olarak kullanilabiliyor (TOTP alternatifi)
- [ ] MFA silme re-auth gerektiriyor
- [ ] Admin login MFA zorunlu (SOC 2 + PCI DSS 8.4.1): MFA enrolled degilse zorla enrollment
- [ ] Admin JWT sadece MFA tamamlandiktan sonra veriliyor

**Bagimlilk:** Faz 0 tamamlanmis

---

## T1.2 — Social Login (OAuth 2.0 + PKCE)

**Ne:** Google, Apple, GitHub, Microsoft ile social login. Authorization Code + PKCE flow.

**Yapilacaklar:**
- `internal/social/service.go` — Provider interface:
  ```go
  type SocialProvider interface {
    AuthURL(state, codeChallenge string) string
    Exchange(ctx context.Context, code, codeVerifier string) (*ProviderUser, error)
  }
  ```
- `internal/social/google.go` — Google OIDC (golang.org/x/oauth2 + PKCE)
- `internal/social/apple.go` — Apple OIDC (id_token dogrulama, Apple'in ozel flow'u)
- `internal/social/github.go` — GitHub OAuth2 (access token → /user API)
- `internal/social/microsoft.go` — Microsoft OIDC (Azure AD v2.0 endpoint)
- `internal/social/handler.go`:
  - `GET /auth/oauth/:provider/authorize`:
    1. PKCE code_verifier + code_challenge uret (S256)
    2. State token uret, Redis'e kaydet (CSRF koruması, 10dk expiry)
    3. Provider auth URL'ine redirect
  - `GET /auth/oauth/:provider/callback`:
    1. State dogrula (Redis'ten, tek kullanimlik)
    2. Authorization code + code_verifier ile provider'dan token al
    3. Provider'dan user profile cek — **GDPR data minimization**: sadece gerekli alanlar saklanir (email, name, avatar). Provider'in dondugu tum response saklanmaz, access/refresh token'lar saklanmaz
    4. **Account linking logic** (spec Section 2.4):
       - Ayni verified email ile mevcut user varsa → `identities` tablosuna ekle, mevcut user'a bagla
       - Yeni email → yeni user olustur + identity kaydet
       - Unverified email ile otomatik linking YASAK
    5. `before.user.create` hook (yeni user ise)
    6. `before.login` hook
    7. **MFA kontrolu**: Eger user.HasMFA → MFA challenge don (social login MFA'yi bypass etmez)
    8. Session olustur, token'lar don
    9. Client redirect_uri'ye redirect (token'larla, veya mfa_required ile)
- `internal/social/credential.go`:
  - `POST /auth/oauth/credential` — Mobile native flow:
    1. Client provider token/id_token gonderir
    2. Server token'i provider'in JWKS/API ile dogrular
    3. Ayni account linking logic
    4. Session olustur, token'lar don

**Project config genislemesi:**
```json
{
  "social_providers": {
    "google": { "client_id": "...", "client_secret": "...", "enabled": true },
    "apple": { "client_id": "...", "team_id": "...", "key_id": "...", "private_key": "...", "enabled": true },
    "github": { "client_id": "...", "client_secret": "...", "enabled": true },
    "microsoft": { "client_id": "...", "client_secret": "...", "tenant": "common", "enabled": true }
  }
}
```

**Endpoint'ler:**
```
GET  /auth/oauth/:provider/authorize → redirect to provider
GET  /auth/oauth/:provider/callback  → handle callback, redirect to client
POST /auth/oauth/credential          → { provider, id_token/access_token } → { access_token, refresh_token, user }
GET  /auth/identities                → kullanicinin bagli social hesaplari
POST /auth/identities/link           → { provider, id_token } → mevcut hesaba social bagla (authenticated)
DELETE /auth/identities/:id          → social hesap ayir (en az 1 auth method kalmali)
```

**Audit event'ler:** `auth.social.login`, `social.link`, `social.unlink`

**Kabul kriterleri:**
- [ ] Google login calisiyor (redirect → consent → callback → token)
- [ ] Apple login calisiyor (Apple'in ozel id_token flow'u)
- [ ] GitHub login calisiyor
- [ ] Microsoft login calisiyor
- [ ] PKCE S256 dogru calisiyor (code_verifier/challenge)
- [ ] State CSRF koruması calisiyor (gecersiz state → hata)
- [ ] Account linking: Ayni verified email → mevcut user'a baglanir
- [ ] Account linking: Unverified email → BAGLAMA YOK, yeni user
- [ ] Mobile credential exchange calisiyor (id_token → session)
- [ ] Social hesap ayirma calisiyor (en az 1 method kalmali kontrolu)
- [ ] Social login + MFA: has_mfa=true user social login yapinca MFA challenge donuyor (bypass yok)
- [ ] Provider config dashboard'dan yonetiliyor
- [ ] Social provider client_secret AES-GCM ile sifreli saklanir

**Bagimlilk:** Faz 0 tamamlanmis

---

## T1.3 — Blocking Hook Engine

**Ne:** Auth pipeline'da senkron blocking hook'lar. Backend "tamam" demeden islem tamamlanmaz.

**Yapilacaklar:**
- `internal/hook/engine.go`:
  - `Execute(ctx context.Context, event string, payload HookPayload) (*HookResponse, error)`:
    1. DB'den project'in bu event icin hook config'ini al
    2. Payload'u JSON'a serialize et
    3. HMAC-SHA256 ile imzala (Standard Webhooks spec header'lari: `webhook-id`, `webhook-timestamp`, `webhook-signature`)
    4. HTTP POST → hook URL'ine gonder
    5. Timeout bekle (default 15sn, configurable)
    6. Response'u parse et: `verdict: "allow"` veya `verdict: "deny"`
    7. Response HMAC imzasini dogrula (bidirectional signing)
    8. Timeout veya hata → failure_mode'a gore davran (`deny` veya `allow`)
  - `HookPayload` struct: spec Section 8.4 formati (event, user, context with risk_score, project)
  - `HookResponse` struct: verdict, metadata, custom_claims, reason

- `internal/hook/middleware.go` — Hook'lari auth akislarina entegre et:
  - `signup.go` → `before.user.create` hook cagir, deny ise user olusturma
  - `login.go` → `before.login` hook cagir, deny ise login reddet
  - `password_reset.go` → `before.password.reset` hook cagir
  - `mfa/totp.go` → `before.mfa.verify` hook cagir (spec Section 8.2)
  - `social/handler.go` → `before.social.link` hook cagir (account linking oncesi, spec Section 8.2)
  - `token/jwt.go` → `before.token.issue` hook cagir (custom claims ekleme — spec Section 8.2)
  - `token/refresh.go` → `before.token.refresh` hook cagir (session risk re-evaluation — spec Section 8.2)
  - Non-blocking hooks (after.*) — webhook sistemi uzerinden degil, **named hook type** olarak da tanimlanir:
    - `after.login.failed` → security monitoring, basarisiz login bildirim
    - `after.session.revoke` → cleanup, kullanici bildirim
  - Hook response'daki `custom_claims` → JWT'ye ekle
  - Hook response'daki `metadata` → audit log'a ekle

**Faz 0'da degisen kodlar:**
- `internal/auth/signup.go` → hook call eklenir (user olusturmadan ONCE)
- `internal/auth/login.go` → hook call eklenir (token vermeden ONCE)
- `internal/auth/password_reset.go` → hook call eklenir

**Endpoint'ler (Admin):**
```
GET    /admin/projects/:id/hooks         → hook config listesi
POST   /admin/projects/:id/hooks         → { event, url, timeout_ms?, failure_mode? } → yeni hook
PUT    /admin/projects/:id/hooks/:hid    → hook guncelle
DELETE /admin/projects/:id/hooks/:hid    → hook sil
POST   /admin/projects/:id/hooks/:hid/test → test payload gonder, response goster
GET    /admin/projects/:id/hooks/:hid/logs → son 100 hook cagri logu (hook_logs tablosundan)
```

**Kabul kriterleri:**
- [ ] `before.user.create` hook calisiyor — deny donerse user olusmaz
- [ ] `before.login` hook calisiyor — deny donerse login reddedilir
- [ ] `before.mfa.verify` hook calisiyor — deny donerse MFA reddedilir (spec Section 8.2)
- [ ] `before.social.link` hook calisiyor — deny donerse account linking reddedilir (spec Section 8.2)
- [ ] `before.token.issue` hook calisiyor — custom claims JWT'ye ekleniyor (spec Section 8.2)
- [ ] `before.token.refresh` hook calisiyor — session risk re-evaluation (spec Section 8.2)
- [ ] `after.login.failed` hook calisiyor — security monitoring icin (spec Section 8.2)
- [ ] `after.session.revoke` hook calisiyor — cleanup icin (spec Section 8.2)
- [ ] HMAC-SHA256 imzalama dogru (Standard Webhooks spec)
- [ ] Bidirectional: Response imzasi da dogrulaniyor
- [ ] Timeout: 15sn icinde cevap gelmezse failure_mode'a gore davranir
- [ ] `failure_mode: "deny"` → timeout'ta islem reddedilir
- [ ] `failure_mode: "allow"` → timeout'ta islem devam eder
- [ ] Hook response'daki `custom_claims` JWT'ye ekleniyor
- [ ] Test hook endpoint calisiyor (dashboard'dan test)
- [ ] Hook loglari goruntulenebiliyor (request, response, latency, status)
- [ ] Replay koruması: ayni webhook-id tekrar islenemez

**Bagimlilk:** Faz 0 tamamlanmis

---

## T1.4 — Webhook Event Delivery (Non-Blocking)

**Ne:** Auth olaylarini harici endpoint'lere bildirim olarak gonderme. Retry, DLQ, replay.

**Yapilacaklar:**
- `internal/webhook/service.go`:
  - `Subscribe(projectID string, sub WebhookSubscription) (secret string, error)`:
    1. HMAC secret uret (256-bit crypto/rand)
    2. Hash'ini DB'ye yaz (`secret_hash`)
    3. Plaintext secret'i sadece bu response'da don (bir daha gosterilemez, API key modeli)
  - `Publish(projectID string, event Event) error`:
    1. Eslesen subscription'lari bul
    2. Her biri icin `webhook_deliveries` tablosuna kayit yaz (status=pending)
    3. Watermill'e publish et (async delivery)
  - HMAC-SHA256 imzalama (Standard Webhooks spec)
  - Idempotency: Her event'te unique `webhook-id` header

- `internal/webhook/worker.go` — Watermill consumer:
  - Pending delivery'leri isler
  - HTTP POST → subscriber URL
  - 2xx → status=success
  - 4xx → status=dlq (client hatasi, retry yok)
  - 5xx / timeout → retry (exponential backoff with jitter):
    ```
    Deneme 1: hemen
    Deneme 2: 1dk sonra
    Deneme 3: 5dk sonra
    Deneme 4: 30dk sonra
    Deneme 5: 2 saat sonra (son — spec Section 19.3: max 5 deneme)
    Basarisiz → status=dlq
    ```
  - Timeout: 30sn per delivery

- `internal/webhook/replay.go`:
  - `Replay(subscriptionID, fromTimestamp)` — belirli tarihten itibaren event'leri tekrar gonder
  - `RetryDLQ(deliveryID)` — DLQ'daki tek bir event'i tekrar dene

**Faz 0'da degisen kodlar:**
- `internal/audit/service.go` → audit log yazdiktan sonra watermill'e publish et
- Her auth event (login, signup, logout, password change, vb.) → webhook publish

**Endpoint'ler (Admin):**
```
GET    /admin/projects/:id/webhooks              → subscription listesi
POST   /admin/projects/:id/webhooks              → { url, events: [...] } → yeni subscription
PUT    /admin/projects/:id/webhooks/:wid         → subscription guncelle
DELETE /admin/projects/:id/webhooks/:wid         → subscription sil
GET    /admin/projects/:id/webhooks/:wid/deliveries → delivery loglar (status, response, latency)
GET    /admin/projects/:id/webhooks/dlq           → dead letter queue
POST   /admin/projects/:id/webhooks/dlq/:did/retry → DLQ'dan tekrar dene
POST   /admin/projects/:id/webhooks/replay        → { from_timestamp } → event replay
```

**Kabul kriterleri:**
- [ ] Event publish calisiyor (login → webhook → subscriber endpoint)
- [ ] HMAC-SHA256 imza dogru (subscriber dogrulayabilir)
- [ ] Retry calisiyor (5xx → 5 deneme, exponential backoff — spec Section 19.3)
- [ ] 4xx → DLQ (retry yok)
- [ ] DLQ'dan manual retry calisiyor
- [ ] Event replay calisiyor (timestamp'ten itibaren)
- [ ] Delivery loglar goruntulenebiliyor (request, response, status, latency)
- [ ] Watermill ile async delivery (Go server bloklanmiyor)

**Bagimlilk:** T1.3 (hook engine ile ayni altyapi), Faz 0 audit log

---

## T1.5 — Magic Link + Session Genisletme

**Ne:** Passwordless email login + session device binding + concurrent session limit.

**Yapilacaklar:**
- `internal/auth/magic_link.go`:
  - `Request(email string)`: Token uret (256-bit), hash DB'ye (verification_tokens, type=magic_link), **15dk expiry**, email gonder
  - `Verify(token string)`: Token dogrula → `before.login` hook → session olustur → token'lar don
  - Rate limit: 1 magic link per 5dk per email

- `internal/session/device.go` — Session device metadata binding:
  - Session create'te IP, user-agent, device fingerprint hash kaydedilir
  - Her request'te mevcut device bilgisi session'daki ile karsilastirilir
  - Major degisiklik (device fingerprint tamamen farkli) → session revoke, re-auth gerekli
  - Minor degisiklik (IP degisti ama ayni ulke) → log + devam

- `internal/session/concurrent.go` — Concurrent session limiti:
  - Project config'den `max_concurrent_sessions` (default: sinirsiz)
  - Limit asildiginda strateji: `deny_new` veya `revoke_oldest`

- `internal/session/trusted.go` — Trusted device registry (spec Section 5.2):
  - "Bu cihazi hatirla" secenegi → device token uretilir (256-bit, SHA-256 hash DB'de, 30 gun)
  - Sonraki girislerde bu token varsa MFA atlanir
  - Max 5 trusted device per user
  - Trusted device revoke edilebilir (dashboard + API)
  - Device fingerprint degisirse trusted token gecersiz olur

**Faz 0'da degisen kodlar:**
- `internal/session/service.go` → device binding + concurrent limit eklenir

**Endpoint'ler:**
```
POST /auth/magic-link         → { email } → { success } (her zaman 200, enumeration yok)
POST /auth/magic-link/verify  → { token } → { access_token, refresh_token, user }
```

**Kabul kriterleri:**
- [ ] Magic link email gonderiliyor (veya console log)
- [ ] Token ile login calisiyor
- [ ] 15dk sonra expired
- [ ] Rate limit: 5dk'da 1 (ayni email)
- [ ] Device binding: Session'a IP + user-agent + fingerprint kaydediliyor
- [ ] Major device degisikligi → session revoke
- [ ] Concurrent limit: max asildiginda oldest revoke (veya deny)
- [ ] Trusted device: "Bu cihazi hatirla" → sonraki login MFA atliyor
- [ ] Trusted device: Max 5 per user
- [ ] Trusted device: 30 gun sonra expire
- [ ] Trusted device: Revoke calisiyor (dashboard + API)
- [ ] Trusted device: Fingerprint degisirse token gecersiz
- [ ] Var olmayan email icin de 200 doner (enumeration koruması)

**Bagimlilk:** Faz 0 (session, email, verification_tokens)

---

## T1.6 — Dashboard Genisletme

**Ne:** Dashboard'a MFA yonetimi, social provider config, hook/webhook yonetimi ekle.

**Yapilacaklar:**
- Project detail → **Authentication genisletme:**
  - Social provider toggle + Client ID/Secret girisi (Google, Apple, GitHub, Microsoft)
  - Provider secret'lar gizli gorunur, tikla goster
- Project detail → **Hooks & Webhooks (yeni sayfa):**
  - Blocking hooks listesi: event, URL, timeout, failure mode, enabled toggle
  - Hook olustur/duzenle/sil
  - "Test Hook" butonu (ornek payload gonder, response gor)
  - Hook cagri loglari (son 100: request/response, latency, status)
  - Webhook subscriptions: URL, event listesi, enabled toggle
  - Delivery loglar: status (success/failed/dlq), response code, latency
  - DLQ gorunumu + retry butonu
- Project detail → **Users genisletme:**
  - MFA durumu gorunur (enrolled/not enrolled, hangi method)
  - MFA reset butonu (admin tarafindan MFA kaldir)
  - Social identities gorunur (hangi provider'lar bagli)
  - Login gecmisi (tarih, IP, auth method, basarili/basarisiz)

**Kabul kriterleri:**
- [ ] Social provider config UI calisiyor (Client ID/Secret gir, toggle)
- [ ] Hook CRUD calisiyor (olustur, duzenle, sil, toggle)
- [ ] Hook test calisiyor (payload gonder, response gor)
- [ ] Hook log stream calisiyor
- [ ] Webhook subscription CRUD calisiyor
- [ ] Webhook delivery loglar gorunuyor
- [ ] DLQ gorunuyor + retry calisiyor
- [ ] User detayda MFA durumu gorunuyor
- [ ] Admin MFA reset calisiyor
- [ ] Login gecmisi gorunuyor

**Bagimlilk:** T1.1-T1.5 (tum Faz 1 endpoint'leri mevcut)

---

## T1.7 — Helm Chart + Production Docker

**Ne:** Kubernetes Helm chart ile production deployment.

**Yapilacaklar:**
- `helm/palauth/` — Helm chart:
  - `Chart.yaml`, `values.yaml`
  - Go server deployment (replicas, resources, probes)
  - Dashboard deployment
  - PostgreSQL (external veya subchart)
  - Redis (external veya subchart)
  - ConfigMap (config.yaml)
  - Secret (pepper, JWT signing key, hook signing keys)
  - Ingress (opsiyonel)
  - HPA (Horizontal Pod Autoscaler, opsiyonel)
- Production Docker image'lar:
  - Go server: multi-stage, scratch base, non-root user, ~15MB
  - Dashboard: Next.js standalone, node-slim base
- `helm install palauth ./helm/palauth --values my-values.yaml`

**Kabul kriterleri:**
- [ ] `helm install` basarili — tum pod'lar Running
- [ ] Health/readiness probe'lari calisiyor
- [ ] Go server + Dashboard erisilebilir (Ingress veya port-forward)
- [ ] Secret'lar Kubernetes Secret'ta (env var'da degil)
- [ ] HPA calisiyor (opsiyonel)

**Bagimlilk:** T1.1-T1.6

---

## T1.8 — SDK Genisletme + Test Sweep

**Ne:** Client ve Server SDK'larina Faz 1 ozelliklerini ekle. Final test sweep.

**Yapilacaklar:**
- OpenAPI spec guncelle (Faz 1 endpoint'leri)
- SDK regenerate:
  - Client SDK: `signInWithOAuth()`, `signInWithCredential()`, `signInWithMagicLink()`, `mfa.enroll()`, `mfa.verify()`, `mfa.challenge()`, `recovery.generateCodes()`, `recovery.useCode()`
  - Server SDK: `hooks.before()`, `on()`, `admin.setCustomClaims()`, `admin.revokeAllSessions()`
- Integration testler:
  - Full MFA flow: signup → MFA enroll → logout → login → MFA challenge → access
  - Social login flow: Google OAuth → callback → session
  - Hook flow: signup with hook → hook deny → user not created
  - Webhook flow: login → webhook delivered → retry on 5xx
  - Magic link flow: request → verify → session
  - Account linking: Google login → same email user exists → linked
  - Recovery code: MFA enrolled → recovery code → access
- Security testler:
  - TOTP replay koruması (ayni kod 30sn icinde tekrar kullanilamaz)
  - Hook HMAC dogrulama (gecersiz imza → reject)
  - State CSRF koruması (gecersiz state → reject)
  - Social login: Unverified email ile auto-link yapilmiyor

**Ek test katmanlari (Faz 0'da kurulan CI/CD pipeline otomatik calisir):**
- DAST: ZAP baseline scan Faz 1 endpoint'lerine karsi (MFA, social, hooks, webhooks)
- Mutation: `internal/mfa/*`, `internal/hook/*` icin gremlins
- Load: k6 MFA challenge endpoint p99 < 500ms
- Chaos: Webhook delivery — Redis down iken queue davranisi

**Kabul kriterleri:**
- [ ] SDK'lar Faz 1 endpoint'lerini destekliyor
- [ ] Tum integration testler geciyor
- [ ] Security testler geciyor
- [ ] Coverage %85+ (guvenlik modulleri %90+)
- [ ] DAST baseline: Faz 1 endpoint'lerinde critical/high yok
- [ ] Mutation score: MFA + hook modulleri %80+

**Bagimlilk:** T1.1-T1.7

---

## Yeni Audit Event'ler (Faz 1 Eklenen)

| Event | Tetikleme |
|-------|-----------|
| `mfa.enroll` | MFA enrollment baslatildi |
| `mfa.verify.success` | MFA dogrulama basarili |
| `mfa.verify.failure` | MFA dogrulama basarisiz |
| `mfa.remove` | MFA kaldirild |
| `mfa.recovery.used` | Recovery code kullanildi |
| `auth.social.login` | Social login basarili |
| `social.link` | Social hesap baglandi |
| `social.unlink` | Social hesap ayrildi |
| `auth.magic_link.request` | Magic link istendi |
| `auth.magic_link.verify` | Magic link ile login |
| `hook.call.success` | Hook basarili cevap |
| `hook.call.failure` | Hook basarisiz/timeout |
| `webhook.delivery.success` | Webhook teslim edildi |
| `webhook.delivery.failure` | Webhook teslim edilemedi |

---

## Bagimlilk Grafi

```
T1.1 (TOTP MFA) ←────── Faz 0 (crypto, user, session, token, audit)
T1.2 (Social Login) ←── Faz 0 (user, session, token, audit)
T1.3 (Hooks) ←───────── Faz 0 (auth flows — signup, login, password reset)
T1.4 (Webhooks) ←─────── T1.3 (hook engine altyapisi), Faz 0 (audit, watermill)
T1.5 (Magic Link) ←───── Faz 0 (session, email, verification_tokens)
T1.6 (Dashboard) ←─────── T1.1-T1.5 (tum Faz 1 endpoint'leri)
T1.7 (Helm) ←───────────── T1.1-T1.6
T1.8 (SDK + Tests) ←────── T1.1-T1.7
```

---

## Haftalik Plan (12 hafta — Ay 5-7)

| Hafta | Task'lar | Not |
|-------|----------|-----|
| 1-2 | T1.1 (TOTP MFA — enroll, verify, challenge, recovery codes) | MFA tam |
| 3-4 | T1.2 (Social login — Google, Apple, GitHub, Microsoft + account linking) | OAuth + PKCE |
| 5-6 | T1.3 (Blocking hooks — engine, HMAC, timeout, failure mode) | Hook pipeline |
| 7-8 | T1.4 (Webhooks — watermill, retry, DLQ, replay) + T1.5 (Magic link + session) | Event delivery + passwordless |
| 9-10 | T1.6 (Dashboard genisletme — MFA, social, hooks, webhooks) | UI |
| 11 | T1.7 (Helm chart + production Docker) | K8s ready |
| 12 | T1.8 (SDK genisletme + final test sweep) | Test + SDK |

**Not:** Her task kendi testini birlikte yazar. T1.8 final sweep.
