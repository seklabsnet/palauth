# PalAuth — Faz 2: Passkeys + Enterprise + Risk Engine (Ay 8-10)

> Hedef: Clerk/WorkOS seviyesi. FIDO2 + OpenID sertifika basvurulari. NIST AAL2 tam uyum (phishing-resistant secenek).
> Faz 0+1 uzerine insa — mevcut kod degistirilmez, genisletilir.
> Paketler: `go-webauthn`, `zitadel/oidc`, `oschwald/geoip2-golang`, `pquerna/otp` (SMS OTP icin de)

---

## Yeni DB Migration'lar

```sql
-- 021_create_webauthn_credentials.up.sql
CREATE TABLE webauthn_credentials (
  id                TEXT PRIMARY KEY NOT NULL,
  project_id        TEXT NOT NULL REFERENCES projects(id),
  user_id           TEXT NOT NULL REFERENCES users(id),
  credential_id     BYTEA NOT NULL,
  public_key        BYTEA NOT NULL,              -- COSE encoded
  attestation_type  TEXT NOT NULL,                -- 'packed', 'none', 'android-key', 'fido-u2f', 'tpm', 'apple'
  aaguid            BYTEA,
  sign_count        BIGINT NOT NULL DEFAULT 0,
  transports        JSONB NOT NULL DEFAULT '[]',  -- ['usb', 'nfc', 'ble', 'internal', 'hybrid']
  backup_eligible   BOOLEAN NOT NULL,             -- BE flag (WebAuthn Level 3)
  backup_state      BOOLEAN NOT NULL,             -- BS flag (WebAuthn Level 3)
  is_passkey        BOOLEAN NOT NULL DEFAULT false,
  is_recovery       BOOLEAN NOT NULL DEFAULT false,
  name              TEXT,                          -- kullanicinin verdigi isim: "iPhone", "YubiKey"
  disabled          BOOLEAN NOT NULL DEFAULT false,-- clone detection sonrasi disable
  last_used_at      TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX idx_wc_cred ON webauthn_credentials(project_id, credential_id);
CREATE INDEX idx_wc_user ON webauthn_credentials(user_id);

-- 022_create_organizations.up.sql
CREATE TABLE organizations (
  id              TEXT PRIMARY KEY NOT NULL,
  project_id      TEXT NOT NULL REFERENCES projects(id),
  name            TEXT NOT NULL,
  slug            TEXT NOT NULL,
  domain          TEXT,
  domain_verified BOOLEAN NOT NULL DEFAULT false,
  settings        JSONB NOT NULL DEFAULT '{}',   -- auth methods, MFA policy, session timeout override
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX idx_org_slug ON organizations(project_id, slug);
CREATE INDEX idx_org_domain ON organizations(domain) WHERE domain_verified = true;

-- 023_create_org_members.up.sql
CREATE TABLE org_members (
  id          TEXT PRIMARY KEY NOT NULL,
  org_id      TEXT NOT NULL REFERENCES organizations(id),
  user_id     TEXT NOT NULL REFERENCES users(id),
  role        TEXT NOT NULL DEFAULT 'member',  -- 'owner', 'admin', 'member', custom
  permissions JSONB NOT NULL DEFAULT '[]',
  invited_by  TEXT REFERENCES users(id),
  joined_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX idx_om_user_org ON org_members(org_id, user_id);

-- 024_create_org_invitations.up.sql
CREATE TABLE org_invitations (
  id          TEXT PRIMARY KEY NOT NULL,
  org_id      TEXT NOT NULL REFERENCES organizations(id),
  email       TEXT NOT NULL,
  role        TEXT NOT NULL DEFAULT 'member',
  token_hash  BYTEA NOT NULL UNIQUE,
  invited_by  TEXT NOT NULL REFERENCES users(id),
  accepted    BOOLEAN NOT NULL DEFAULT false,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at  TIMESTAMPTZ NOT NULL             -- 7 gun
);
CREATE INDEX idx_oi_token ON org_invitations(token_hash) WHERE accepted = false;

-- 025_create_oauth_clients.up.sql (OIDC Provider icin)
CREATE TABLE oauth_clients (
  id              TEXT PRIMARY KEY NOT NULL,
  project_id      TEXT NOT NULL REFERENCES projects(id),
  client_id       TEXT NOT NULL UNIQUE,
  client_secret_hash BYTEA,                    -- confidential clients
  client_type     TEXT NOT NULL CHECK (client_type IN ('confidential', 'public')),
  redirect_uris   JSONB NOT NULL DEFAULT '[]',
  grant_types     JSONB NOT NULL DEFAULT '["authorization_code"]',
  scopes          JSONB NOT NULL DEFAULT '["openid", "profile", "email"]',
  token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_basic',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 026_create_risk_signals.up.sql
CREATE TABLE risk_signals (
  id          TEXT PRIMARY KEY NOT NULL,
  project_id  TEXT NOT NULL,
  user_id     TEXT,
  session_id  TEXT,
  signal_type TEXT NOT NULL,    -- 'impossible_travel', 'new_device', 'vpn_tor', 'velocity', 'bot'
  score       REAL NOT NULL,    -- 0.0-1.0
  details     JSONB,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_rs_user ON risk_signals(user_id, created_at DESC);

-- 027_add_users_phone.up.sql (SMS OTP icin)
ALTER TABLE users ADD COLUMN phone_encrypted BYTEA;
ALTER TABLE users ADD COLUMN phone_hash BYTEA;
ALTER TABLE users ADD COLUMN phone_verified BOOLEAN NOT NULL DEFAULT false;
CREATE INDEX idx_users_phone ON users(project_id, phone_hash) WHERE phone_hash IS NOT NULL;
```

---

## T2.1 — WebAuthn / Passkeys

**Ne:** FIDO2/WebAuthn registration + authentication. Passkey-first kayit. BE/BS flag parsing. Clone detection. FIDO MDS v3.

**Yapilacaklar:**
- `internal/webauthn/service.go` — `go-webauthn/webauthn` wrapper:
  - `BeginRegistration(user, project) (*protocol.CredentialCreation, sessionData, error)`:
    1. Challenge uret (16+ byte crypto/rand, tek kullanimlik)
    2. rpId = project config'den (veya domain)
    3. PublicKeyCredentialCreationOptions dondur
    4. Session data Redis'te sakla (challenge + user bilgisi)
  - `FinishRegistration(sessionData, response) (*WebAuthnCredential, error)`:
    1. Attestation object parse et (CBOR)
    2. Attestation format dogrula: **packed** (zorunlu), **none** (zorunlu), **android-key** (zorunlu), fido-u2f, tpm, apple
    3. Sertifika zinciri dogrula (packed full attestation icin)
    4. rpIdHash dogrula
    5. signCount = 0 kontrol (ilk kayit)
    6. **BE/BS flag'leri parse et** (WebAuthn Level 3):
       - BE=0, BS=0 → device-bound, AAL3 uygun
       - BE=1, BS=0 → sync-eligible, henuz yedeklenmemis → kullaniciya uyari
       - BE=1, BS=1 → synced passkey, AAL2 uygun
       - BE=0, BS=1 → GECERSIZ → reddet
    7. AAGUID al → FIDO MDS v3 sorgula (compromised authenticator tespiti)
    8. Public key + credential ID + attestation type + flags → DB'ye kaydet
  - `BeginAuthentication(user, project) (*protocol.CredentialAssertion, sessionData, error)`
  - `FinishAuthentication(sessionData, response) (*WebAuthnCredential, error)`:
    1. Signature dogrula (stored public key ile)
    2. Challenge match
    3. rpIdHash dogrula
    4. UP (User Presence) flag kontrol
    5. UV (User Verification) flag kontrol
    6. **signCount kontrol**: Eger yeni signCount <= stored signCount → CLONE DETECTED
       - `device.suspicious` audit event log
       - Credential'i disable et veya admin'e alert
    7. BS flag'i guncelle (her ceremony'de degisebilir)
    8. signCount guncelle

- `internal/webauthn/passkey.go`:
  - Passkey-first kayit: Sifre olusturmadan sadece passkey ile kayit
    - `before.user.create` hook cagrilir (Faz 1 hook engine — tum signup akislari hook'tan gecer)
    - User olusturulur (password_hash = NULL)
    - WebAuthn credential kaydedilir
  - Cross-device QR login: WebAuthn hybrid transport (`transports: ["hybrid"]`)
  - Passkey listesi: Kullanicinin tum passkey'leri (isim, son kullanim, platform, backup durumu)
  - **Recovery passkey** (spec Section 11.1.3):
    - Ikinci cihaza kayitli yedek passkey, `is_recovery = true` flag ile
    - Sadece recovery islemlerinde kullanilabilir, normal login icin kullanilmaz
    - Recovery sirasinda: tum session'lar sonlandirilir + yeni MFA enrollment zorunlu (spec Section 11.2)

- `internal/webauthn/mds.go`:
  - FIDO MDS v3 entegrasyonu
  - AAGUID → authenticator metadata lookup
  - Compromised/revoked authenticator tespiti
  - MDS blob'u periyodik cache'le (24 saatte bir yenile)

**Faz 0-1'de degisen kodlar:**
- `internal/auth/login.go` → WebAuthn MFA olarak veya passwordless olarak ekle:
  ```go
  if authMethod == "passkey" {
    // Passwordless — password verify yok, direkt WebAuthn
    acr = determineAAL(credential)  // BE=0 → aal3, BE=1 → aal2
  }
  ```
- Session create'te: WebAuthn ile login → `amr = ["hwk"]` (hardware key) veya `amr = ["swk"]` (software key / synced passkey)
- **AAL2 phishing-resistant secenek artik sunuluyor** (NIST 800-63B-4 Sec 2.2.2 SHALL karsilandi)

**Endpoint'ler:**
```
POST /auth/webauthn/register/begin    → { } → { options: PublicKeyCredentialCreationOptions }
POST /auth/webauthn/register/finish   → { attestation } → { credential_id, backup_eligible, backup_state }
POST /auth/webauthn/login/begin       → { email? } → { options: PublicKeyCredentialRequestOptions }
POST /auth/webauthn/login/finish      → { assertion } → { access_token, refresh_token, user }
GET  /auth/webauthn/credentials       → passkey listesi
PUT  /auth/webauthn/credentials/:id   → { name } → passkey yeniden adlandir
DELETE /auth/webauthn/credentials/:id → passkey sil (en az 1 auth method kalmali)
```

**Audit event'ler:** `webauthn.register`, `webauthn.login`, `webauthn.remove`, `webauthn.clone_detected`

**Kabul kriterleri:**
- [ ] Passkey registration calisiyor (Chrome, Safari, Firefox)
- [ ] Passkey login calisiyor (passwordless)
- [ ] Packed attestation dogrulamasi calisiyor
- [ ] None attestation kabul ediliyor
- [ ] android-key attestation calisiyor
- [ ] BE/BS flag'leri dogru parse ediliyor ve DB'ye kaydediliyor
- [ ] BE=0 credential → AAL3 izin, BE=1 → max AAL2
- [ ] BE=0, BS=1 → reddediliyor (gecersiz kombinasyon)
- [ ] Clone detection: signCount regression → alert + credential disable
- [ ] FIDO MDS v3: Compromised authenticator → uyari
- [ ] Cross-device QR login calisiyor (hybrid transport)
- [ ] Passkey-first kayit: Sifresiz kullanici olusturuyor
- [ ] Passkey listesi: isim, son kullanim, backup durumu gorunuyor
- [ ] Passkey silme: En az 1 auth method kontrolu
- [ ] rpId ve origin dogrulamasi dogru
- [ ] ES256 algoritma ile imzalanmis credential dogrulanabiliyor (zorunlu minimum algoritma)
- [ ] Recovery passkey: is_recovery=true ile kaydediliyor
- [ ] Recovery passkey: Normal login'de kullanilamaz, sadece recovery'de
- [ ] Recovery sonrasi: Tum session'lar sonlandirilir + yeni MFA enrollment zorunlu

**Bagimlilk:** Faz 0 (user, session, token, audit), Faz 1 (MFA flow)

---

## T2.2 — Step-Up Authentication (RFC 9470)

**Ne:** Hassas islemler icin mevcut session uzerinde ek dogrulama. ACR/AMR bazli.

**Yapilacaklar:**
- `internal/stepup/service.go`:
  - `Check(session, requiredACR string) error`:
    1. Session'daki `acr` ile `requiredACR` karsilastir
    2. Yetersiz ise → RFC 9470 hatasi don:
       ```
       HTTP 401
       WWW-Authenticate: Bearer error="insufficient_user_authentication",
         acr_values="urn:nist:800-63:aal2",
         max_age=300
       ```
    3. Client step-up flow baslatir
  - `Execute(session, method string) (*StepUpToken, error)`:
    1. Ek dogrulama yap (TOTP, WebAuthn, vb.)
    2. Basarili → session'in `acr` ve `amr` guncelle
    3. Step-up token uret (kisa omurlu: 5-15dk, configurable)
    4. Yeni JWT issue (yuksek ACR ile)
  - `acr_values_supported` → OIDC discovery metadata'ya ekle

- `internal/stepup/middleware.go`:
  - `RequireACR(level string)` — Chi middleware, endpoint'e ACR zorunlulugu ekler
  - Kullanim: `r.With(RequireACR("aal2")).Post("/sensitive-action", handler)`

**Faz 0-1'de degisen kodlar:**
- `/.well-known/openid-configuration` → `acr_values_supported` eklenir
- JWT claims'e `acr` ve `auth_time` zaten var (Faz 0'dan)

**Endpoint'ler:**
```
POST /auth/step-up         → { method: "totp"|"webauthn", code? } → { access_token (yuksek ACR) }
GET  /auth/step-up/status  → { current_acr, required_acr, methods_available }
```

**Kabul kriterleri:**
- [ ] AAL1 session ile AAL2 endpoint'e erisim → 401 + `insufficient_user_authentication`
- [ ] Step-up TOTP ile → session acr=aal2, yeni JWT
- [ ] Step-up WebAuthn (device-bound) ile → session acr=aal3, yeni JWT
- [ ] Step-up token 5-15dk sonra expire
- [ ] `acr_values_supported` OIDC discovery'de gorunuyor
- [ ] `auth_time` claim step-up sonrasi guncelleniyor

**Bagimlilk:** T2.1 (WebAuthn), Faz 1 (MFA)

---

## T2.3 — Risk Engine

**Ne:** Her auth islemi icin 0.0-1.0 risk skoru hesaplama. Pluggable sinyal sistemi.

**Yapilacaklar:**
- `internal/risk/engine.go`:
  - `Evaluate(ctx context.Context, req RiskRequest) (*RiskResult, error)`:
    1. Tum signal provider'lari calistir (paralel)
    2. Her sinyalin skorunu agirlikla carp
    3. Toplam skor hesapla: `sum(weight * score) / sum(weights)`
    4. Sonucu `risk_signals` tablosuna yaz
    5. Aksiyonu belirle:
       - 0.0-0.3 → Allow
       - 0.3-0.6 → Step-up auth (MFA challenge)
       - 0.6-0.8 → Siki step-up (hardware key zorunlu)
       - 0.8-1.0 → Block + bildirim + admin alert
    6. Skor hook payload'unda `context.risk_score` olarak iletilir

- `internal/risk/signals/` — Signal provider'lar:
  - `ip_geo.go` — `oschwald/geoip2-golang` ile:
    - IP → ulke, sehir
    - Impossible travel: Son login ile mesafe/zaman orani (Haversine formula, >500mph → flag)
    - VPN/Tor/proxy/hosting tespiti (GeoLite2 ASN DB)
  - `device.go`:
    - Bilinmeyen cihaz (ilk kez gorulme) → orta risk
    - Device fingerprint degisimi → yuksek risk
  - `velocity.go`:
    - Kisa surede cok fazla islem → yuksek risk
    - Basarisiz login gecmisi (son 1 saat) → orta risk
  - `bot.go`:
    - PoW challenge sonucu → sinyal
    - Credential stuffing pattern tespiti

- `internal/risk/connector.go` — Pluggable connector interface:
  ```go
  type SignalProvider interface {
    Name() string
    Weight() float64
    Evaluate(ctx context.Context, req RiskRequest) (float64, error)
  }
  ```
  Ucuncu parti connectors (Faz 3+): Fingerprint.com, MaxMind, Arkose Labs

**Faz 0-1'de degisen kodlar:**
- `internal/auth/login.go` → risk engine evaluate ekle:
  ```go
  risk := riskEngine.Evaluate(ctx, req)
  if risk.Action == "block" { return blocked }
  if risk.Action == "step_up" { return stepUpRequired }
  ```
- `internal/auth/signup.go` → risk engine evaluate ekle (bot/stuffing tespiti signup'ta da calisir)
- Hook payload'da `context.risk_score` artik gercek deger (Faz 0'da 0.0 idi)

**Project config:**
```json
{
  "risk_engine": {
    "enabled": true,
    "thresholds": { "step_up": 0.3, "strict_step_up": 0.6, "block": 0.8 },
    "signals": {
      "ip_geo": { "enabled": true, "weight": 0.5 },
      "device": { "enabled": true, "weight": 0.4 },
      "velocity": { "enabled": true, "weight": 0.3 },
      "bot": { "enabled": true, "weight": 0.4 }
    }
  }
}
```

**Kabul kriterleri:**
- [ ] Risk skoru 0.0-1.0 arasinda hesaplaniyor
- [ ] Impossible travel: Farkli ulkelerden kisa surede login → yuksek skor
- [ ] VPN/Tor tespiti calisiyor (GeoLite2 ASN)
- [ ] Bilinmeyen cihaz → orta risk skor
- [ ] Velocity: 10 basarisiz login/saat → yuksek skor
- [ ] Skor > threshold → step-up auth tetikleniyor
- [ ] Skor > block threshold → login reddediliyor + admin alert
- [ ] Risk skoru hook payload'unda `context.risk_score` olarak iletiliyor
- [ ] Risk skoru audit log'da kaydediliyor
- [ ] Esik degerleri project config'den yapilandirilabiliyor
- [ ] Risk sinyalleri DB'ye kaydediliyor (forensic analiz icin)

**Bagimlilk:** Faz 0 (session, audit), Faz 1 (hooks — risk_score payload)

---

## T2.4 — Bot Detection (Proof-of-Work)

**Ne:** Self-hostable PoW challenge. Rate limiting + risk engine ile entegre.

**Yapilacaklar:**
- `internal/bot/pow.go`:
  - `GenerateChallenge(difficulty int) (*Challenge, error)`:
    1. Random prefix uret
    2. Difficulty (kac bit sifir) project config'den
    3. Challenge + difficulty + expiry don
  - `VerifyChallenge(challenge, nonce string) (bool, error)`:
    1. SHA256(challenge + nonce) hesapla
    2. Ilk N bit sifir mi kontrol et
    3. Challenge expired mi kontrol et
    4. Challenge daha once kullanildi mi kontrol et (replay koruması)
  - Zorluk dinamik: risk skoru yukseldikce puzzle zorlasir

- `internal/bot/middleware.go`:
  - Configurable: Hangi endpoint'lerde PoW gerekli
  - Default: `/auth/signup`, `/auth/login` (risk skoru > 0.3 ise)
  - PoW basarisiz → 403

- `internal/bot/stuffing.go`:
  - Credential stuffing tespiti:
    - Cok farkli hesaba ayni IP'den login denemesi
    - Dusuk basari orani (<%5) + yuksek hacim (>50/saat)
    - Otomatik IP bloklama (Redis'te, configurable sure)
  - Risk engine'e sinyal olarak iletir

**Kabul kriterleri:**
- [ ] PoW challenge uretiliyor ve dogrulanabiliyor
- [ ] Zorluk dinamik — risk skoru yukseldikce zorlasir
- [ ] Replay koruması: Ayni challenge tekrar kullanilamaz
- [ ] Credential stuffing tespiti calisiyor
- [ ] Otomatik IP bloklama calisiyor
- [ ] Risk engine'e bot sinyal gidiyor
- [ ] GDPR: PoW challenge'da cookie/fingerprint/tracking YOK (spec Section 10.1)

**Bagimlilk:** T2.3 (risk engine)

---

## T2.5 — Organizations (B2B Temel)

**Ne:** B2B organization yapisi. Roller, davet, domain verification.

**Yapilacaklar:**
- `internal/org/service.go`:
  - `Create(projectID, name, slug)` → org olustur, olusturani owner yap
  - `Get`, `Update`, `Delete`, `List`
  - `AddMember(orgID, userID, role)` → uye ekle
  - `RemoveMember(orgID, userID)` → uye cikar
  - `UpdateRole(orgID, userID, newRole)` → rol degistir
  - `ListMembers(orgID, filters, pagination)` → cursor-based pagination

- `internal/org/invitation.go`:
  - `Invite(orgID, email, role, invitedBy)`:
    1. Token uret (256-bit), hash DB'ye, 7 gun expiry
    2. Davet email'i gonder
  - `Accept(token)`:
    1. Token dogrula (hash, expiry, kullanilmamis)
    2. Mevcut user → org'a ekle
    3. Yeni user → signup + org'a ekle

- `internal/org/domain.go`:
  - `VerifyDomain(orgID, domain)`:
    1. DNS TXT record kontrol: `_palauth-verify=<token>`
    2. Basarili → `domain_verified = true`
    3. Verified domain → bu domain email'li yeni user'lar otomatik org'a eklenir (configurable: auto-add veya approval-required)

- Roller: `owner` (tek), `admin`, `member` + custom roller (max 20 per org)
- Izinler: `resource.action` format (ornek: `members.invite`, `settings.update`)
- JWT'ye org claim: `{ "org_id": "org_xxx", "org_role": "admin" }`

**Endpoint'ler:**
```
POST   /admin/projects/:id/organizations          → { name, slug }
GET    /admin/projects/:id/organizations          → { orgs: [...] }
GET    /admin/projects/:id/organizations/:oid     → org detay + members
PUT    /admin/projects/:id/organizations/:oid     → { name, settings }
DELETE /admin/projects/:id/organizations/:oid

POST   /admin/projects/:id/organizations/:oid/members     → { user_id, role }
PUT    /admin/projects/:id/organizations/:oid/members/:uid → { role }
DELETE /admin/projects/:id/organizations/:oid/members/:uid

POST   /admin/projects/:id/organizations/:oid/invitations → { email, role }
POST   /auth/invitations/accept → { token } → signup/login + org join

POST   /admin/projects/:id/organizations/:oid/domain/verify → { domain }
GET    /admin/projects/:id/organizations/:oid/domain/status → { verified, dns_record }
```

**Audit event'ler:** `org.create`, `org.update`, `org.delete`, `org.member.add`, `org.member.remove`, `org.member.role_change`, `org.invitation.send`, `org.invitation.accept`, `org.domain.verify`

**Kabul kriterleri:**
- [ ] Org CRUD calisiyor
- [ ] Member ekleme/cikarma/rol degistirme calisiyor
- [ ] Davet sistemi calisiyor (email + 7 gun token)
- [ ] Davet kabul → mevcut user org'a ekleniyor
- [ ] Davet kabul → yeni user signup + org join
- [ ] Domain verification calisiyor (DNS TXT record)
- [ ] Verified domain → yeni user otomatik org'a ekleniyor
- [ ] Custom roller calisiyor (max 20 per org)
- [ ] JWT'de org_id + org_role claim'leri var
- [ ] Org-scoped audit loglar goruntulenebiliyor

**Bagimlilk:** Faz 0 (user, audit), Faz 1 (email)

---

## T2.6 — OpenID Connect Provider

**Ne:** PalAuth OIDC Provider olarak calisir. Baska uygulamalar "PalAuth ile giris yap" yapabilir.

**Yapilacaklar:**
- `internal/oidc/provider.go` — `zitadel/oidc` v3 ile OP (OpenID Provider) kurulumu:
  - Discovery: `GET /.well-known/openid-configuration`
  - Authorization: `GET /oauth/authorize` (Auth Code + PKCE)
  - Token: `POST /oauth/token`
  - UserInfo: `GET /oauth/userinfo`
  - JWKS: `GET /.well-known/jwks.json` (Faz 0'dan mevcut, genisletilir)
  - Dynamic client registration: `POST /oauth/register` (RFC 7591)
  - Logout: RP-Initiated (`GET /oauth/logout`), back-channel (`POST /oauth/backchannel-logout`)

- `internal/oidc/client.go`:
  - OAuth client CRUD (Admin API ile)
  - Client ID + Secret uretimi
  - Redirect URI validation (exact string match — OAuth 2.1)
  - Grant type validation

- OpenID Connect conformance test suite'ini gecirecek sekilde implement et
  - Hedeflenen profiller: Basic OP, Config OP

**Endpoint'ler:**
```
GET  /.well-known/openid-configuration → discovery metadata
GET  /oauth/authorize                   → authorization endpoint
POST /oauth/token                       → token endpoint
GET  /oauth/userinfo                    → userinfo endpoint
POST /oauth/register                    → dynamic client registration
GET  /oauth/logout                      → RP-initiated logout
POST /oauth/backchannel-logout          → back-channel logout notification

POST   /admin/projects/:id/oauth-clients     → client olustur
GET    /admin/projects/:id/oauth-clients     → client listesi
GET    /admin/projects/:id/oauth-clients/:cid → client detay
PUT    /admin/projects/:id/oauth-clients/:cid → client guncelle
DELETE /admin/projects/:id/oauth-clients/:cid → client sil
```

**Kabul kriterleri:**
- [ ] Discovery endpoint dogru metadata donuyor
- [ ] Authorization Code + PKCE flow calisiyor (end-to-end)
- [ ] Token endpoint dogru JWT donuyor (id_token + access_token)
- [ ] UserInfo endpoint dogru claims donuyor
- [ ] Dynamic client registration calisiyor
- [ ] RP-Initiated logout calisiyor
- [ ] Back-channel logout calisiyor
- [ ] Redirect URI exact match (wildcard yok)
- [ ] `acr_values` parameter destekli — client AAL2 isteyebilir
- [ ] `unmet_authentication_requirements` error donuyor (AS karsilayamiyorsa — spec Section 3.4)
- [ ] OpenID Connect Basic OP conformance test suite GECIYOR
- [ ] OpenID Connect Config OP conformance test suite GECIYOR

**Bagimlilk:** Faz 0 (token, JWKS), Faz 1 (auth flows)

---

## T2.7 — SMS OTP

**Ne:** SMS ile OTP dogrulama. NIST restricted, sadece fallback.

**Yapilacaklar:**
- `internal/mfa/sms.go`:
  - SMS provider interface:
    ```go
    type SMSProvider interface {
      Send(ctx context.Context, to, message string) error
    }
    ```
  - Twilio implementation
  - Console implementation (dev modu)
  - OTP: 6 haneli, 5dk expiry (PSD2 RTS), replay koruması
  - Phone number: E.164 format, ulke bazli whitelist/blacklist
  - Rate limit: 1 SMS per 1dk per numara

- NIST 800-63B restricted uyarisi:
  - SMS OTP secildiginde kullaniciya SIM-swap riski uyarisi gosterilir
  - Project config ile devre disi birakilabilir (`sms_otp_enabled: false`)
  - Yuksek guvenlik modunda otomatik devre disi

**Endpoint'ler:**
```
POST /auth/mfa/sms/enroll   → { phone } → SMS kodu gonderilir
POST /auth/mfa/sms/verify   → { code } → enrollment dogrula
POST /auth/mfa/sms/challenge → { mfa_token, code } → MFA dogrula
```

**Kabul kriterleri:**
- [ ] SMS OTP gonderiliyor (Twilio veya console)
- [ ] 6 haneli, 5dk expiry
- [ ] Rate limit: 1/dk per numara
- [ ] Replay koruması: Ayni kod tekrar kullanilamaz
- [ ] Ulke whitelist/blacklist calisiyor
- [ ] Restricted uyarisi gorunuyor
- [ ] Project config ile devre disi birakilabiliyor
- [ ] Phone E.164 format validation

**Bagimlilk:** Faz 0 (crypto, rate limit), Faz 1 (MFA flow)

---

## T2.8 — Key Rotation (Automated)

**Ne:** JWT signing key otomatik rotation. JWKS'te eski + yeni key.

**Yapilacaklar:**
- `internal/token/rotation.go`:
  - Configurable rotation period (default 90 gun, PCI DSS/SOC 2)
  - Rotation akisi:
    1. Yeni key pair uret
    2. JWKS endpoint'e ekle (eski + yeni birlikte)
    3. Grace period (default 24 saat) — client'lar cache yeniler
    4. Yeni key aktif signer olur
    5. Eski key sadece dogrulama icin kalir
    6. `retirement_time + max_token_lifetime + buffer` sonra eski key kaldirilir
  - Background job: Rotation schedule kontrol
  - Admin API: Manuel rotation tetikleme

**Endpoint'ler:**
```
POST /admin/keys/rotate → { } → manuel key rotation tetikle
GET  /admin/keys        → { keys: [...], active_kid, next_rotation }
```

**Audit event'ler:** `admin.key.rotate`

**Kabul kriterleri:**
- [ ] Otomatik rotation calisiyor (90 gun)
- [ ] JWKS endpoint'te eski + yeni key birlikte gorunuyor
- [ ] Eski key ile imzalanmis token'lar hala dogrulanabiliyor
- [ ] Grace period sonrasi eski key kaldirilabiliyor
- [ ] Manuel rotation calisiyor
- [ ] kid dogru set ediliyor (yeni token'larda yeni kid)

**Bagimlilk:** Faz 0 (token, JWKS)

---

## T2.9 — SDK'lar (NestJS + Edge + KMP)

**Ne:** 3 yeni SDK: NestJS decorator-based, Edge JWT dogrulama, KMP mobile.

**Yapilacaklar:**
- `sdk/typescript/nestjs/` — `@palauth/nestjs`:
  - `AuthServerModule.register({ url, serviceKey, hooks })` — NestJS module
  - `@RequireAuth()` — guard decorator (AAL1 yeterli)
  - `@RequireAuth({ acr: 'aal2', mfa: true })` — step-up zorunlu
  - `@CurrentUser()` — param decorator
  - Hook handler interface: `AuthHookHandler`
  - `@palauth/server` uzerine kurulu

- `sdk/typescript/edge/` — `@palauth/edge`:
  - `createVerifier({ jwksUrl, issuer, audience })` — Edge runtime JWT verifier
  - `verifier.verify(token)` → `{ valid, claims, error }`
  - `verifier.verifyDPoP(proof, token, request)` → DPoP dogrulama (Faz 3 icin hazir)
  - `verifier.checkAcr(claims, requiredAcr)` → ACR kontrol
  - JWKS caching (configurable TTL)
  - <50KB bundle, Web Crypto API, sifir dependency
  - Cloudflare Workers + Vercel Edge + Deno Deploy uyumlu

- `sdk/mobile/` — `palauth-mobile` (KMP):
  - Kotlin Multiplatform: shared code + platform-specific
  - `PalAuth.create(url, apiKey)` → client
  - Auth methods: signIn, signUp, signOut, passkey.register/authenticate
  - Token persistence: Android EncryptedSharedPreferences, iOS Keychain
  - Auto-refresh, PKCE, onAuthStateChange
  - Platform-specific: BiometricPrompt (Android), LAContext (iOS)

**Kabul kriterleri:**
- [ ] NestJS SDK: `@RequireAuth()` guard calisiyor
- [ ] NestJS SDK: `@RequireAuth({ acr: 'aal2' })` step-up zorunlulugu calisiyor
- [ ] NestJS SDK: `@CurrentUser()` decorator dogru user donuyor
- [ ] Edge SDK: JWT dogrulama calisiyor (Cloudflare Workers'da)
- [ ] Edge SDK: <50KB bundle size
- [ ] Edge SDK: JWKS caching calisiyor
- [ ] KMP SDK: Android + iOS login calisiyor
- [ ] KMP SDK: Passkey registration/authentication calisiyor
- [ ] KMP SDK: Token auto-refresh calisiyor

**Bagimlilk:** T2.1-T2.8 (tum endpoint'ler), Faz 0-1 (OpenAPI spec)

---

## T2.10 — Dashboard Genisletme + Test Sweep

**Ne:** Dashboard'a org, security, analytics sayfalari ekle. Final test sweep.

**Yapilacaklar:**
- Project detail → **Organizations (yeni sayfa):**
  - Org listesi, olusturma, duzenleme
  - Member yonetimi (davet, rol degistirme, cikarma)
  - Domain verification UI
- Project detail → **Security (yeni sayfa):**
  - Risk engine esik degerleri yapilandirma
  - IP whitelist/blacklist yonetimi
  - Geo-blocking (ulke bazli acik/kapali)
  - Bot detection ayarlari (PoW zorlugu)
  - Rate limit override
- Project detail → **Analytics (genisletme):**
  - Auth method dagilimi (pie chart: password vs social vs passkey)
  - MFA adoption orani (trend)
  - Risk score dagilimi (histogram)
  - Login basari/basarisizlik trendi

**Test sweep:**
- Integration testler:
  - Full WebAuthn flow: register → login (passwordless)
  - Step-up: AAL1 login → AAL2 endpoint → step-up → access
  - Risk engine: VPN'den login → step-up tetiklenir
  - Org: Olustur → davet → kabul → member listesi
  - OIDC: Client register → auth code flow → token → userinfo
  - Clone detection: signCount regression → alert
  - SMS OTP: Enroll → challenge → verify
- Security testler:
  - BE/BS flag parsing (tum 4 kombinasyon)
  - OIDC conformance suite (Basic OP, Config OP)
  - FIDO2 conformance testi (attestation formats)
- Coverage: %85+ (guvenlik modulleri %90+)

**Kabul kriterleri:**
- [ ] Dashboard org yonetimi calisiyor
- [ ] Dashboard risk engine config calisiyor
- [ ] Dashboard analytics grafikleri gorunuyor
- [ ] Tum integration testler geciyor
- [ ] OpenID Connect conformance suite geciyor
- [ ] FIDO2 conformance testleri geciyor
- [ ] Coverage %85+

**Bagimlilk:** T2.1-T2.9

---

## Yeni Audit Event'ler (Faz 2 Eklenen)

| Event | Tetikleme |
|-------|-----------|
| `webauthn.register` | Passkey kaydi |
| `webauthn.login` | Passkey ile login |
| `webauthn.remove` | Passkey silindi |
| `webauthn.clone_detected` | signCount regression |
| `auth.step_up.success` | Step-up basarili |
| `auth.step_up.failure` | Step-up basarisiz |
| `risk.evaluate` | Risk skoru hesaplandi |
| `risk.block` | Risk sebebiyle login bloklandi |
| `bot.pow.challenge` | PoW challenge gonderildi |
| `bot.stuffing.detected` | Credential stuffing tespit |
| `bot.ip.blocked` | IP otomatik bloklandi |
| `org.*` | Organization event'leri (9 event) |
| `oidc.authorize` | OIDC authorization request |
| `oidc.token.issue` | OIDC token verildi |
| `sms.otp.send` | SMS OTP gonderildi |
| `admin.key.rotate` | JWT key rotate edildi |

---

## Haftalik Plan (12 hafta — Ay 8-10)

| Hafta | Task'lar | Not |
|-------|----------|-----|
| 1-3 | T2.1 (WebAuthn/Passkeys — registration, authentication, BE/BS, MDS v3, clone detection) | En karmasik task |
| 4 | T2.2 (Step-up auth — RFC 9470, ACR/AMR, middleware) | WebAuthn ile birlikte AAL2/AAL3 |
| 5-6 | T2.3 (Risk engine — signals, scoring, thresholds) + T2.4 (Bot detection — PoW, stuffing) | Security katmani |
| 7-8 | T2.5 (Organizations — CRUD, members, invitations, domain verify) | B2B |
| 9-10 | T2.6 (OIDC Provider — zitadel/oidc, discovery, auth code, userinfo) + T2.7 (SMS OTP) | Protocols |
| 11 | T2.8 (Key rotation) + T2.9 (SDK'lar — NestJS, Edge, KMP) | Infra + SDK |
| 12 | T2.10 (Dashboard + conformance tests + test sweep) | Final |

**Not:** Her task kendi testini birlikte yazar. T2.10 final sweep + conformance.
