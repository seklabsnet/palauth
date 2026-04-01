# PalAuth — Faz 3: Financial-Grade (Ay 11-16)

> Hedef: Auth0 seviyesi + device attestation + PSD2 SCA + FAPI 2.0. SAML 2-4 ay surebilir.
> Faz 0+1+2 uzerine insa — mevcut kod degistirilmez, genisletilir.
> Paketler: `AxisCommunications/go-dpop`, `crewjam/saml`, `elimity-com/scim`, `google.golang.org/api/playintegrity/v1`, `splitsecure/go-app-attest`

---

## Yeni DB Migration'lar

```sql
-- 028_create_devices.up.sql
-- Not: Faz 0 sessions tablosundaki device_fp_hash = passive fingerprint (UA, screen, etc.)
-- Bu devices tablosu = active cryptographic binding (hardware enclave key pair + platform attestation)
-- Farkli amaclar: session.device_fp_hash anomaly detection icin, devices.public_key transaction signing icin
CREATE TABLE devices (
  id                  TEXT PRIMARY KEY NOT NULL,
  project_id          TEXT NOT NULL REFERENCES projects(id),
  user_id             TEXT NOT NULL REFERENCES users(id),
  platform            TEXT NOT NULL CHECK (platform IN ('android', 'ios', 'web')),
  device_name         TEXT,
  public_key          BYTEA,                     -- cryptographic device binding key (ECDSA P-256)
  attestation_status  TEXT NOT NULL DEFAULT 'pending' CHECK (attestation_status IN ('pending', 'verified', 'failed', 'revoked')),
  attestation_data    JSONB,                     -- Play Integrity verdict / App Attest attestation
  sign_count          BIGINT NOT NULL DEFAULT 0, -- device binding request signing counter
  trusted             BOOLEAN NOT NULL DEFAULT false,
  trusted_until       TIMESTAMPTZ,
  last_attestation_at TIMESTAMPTZ,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at        TIMESTAMPTZ
);
CREATE INDEX idx_devices_user ON devices(user_id) WHERE attestation_status = 'verified';

-- 029_create_transactions.up.sql
CREATE TABLE transactions (
  id              TEXT PRIMARY KEY NOT NULL,
  project_id      TEXT NOT NULL REFERENCES projects(id),
  user_id         TEXT NOT NULL REFERENCES users(id),
  device_id       TEXT REFERENCES devices(id),
  amount          DECIMAL(20, 4),
  currency        TEXT,
  payee_id        TEXT,
  payee_name      TEXT,
  challenge       TEXT NOT NULL,                  -- server_nonce || amount || payee_id || timestamp
  challenge_hash  TEXT NOT NULL,                  -- SHA-256(challenge) — imza dogrulama icin
  device_signature BYTEA,                         -- client TEE private key ile imzalanmis
  status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
  expires_at      TIMESTAMPTZ NOT NULL,           -- max 5dk (PSD2 RTS)
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at    TIMESTAMPTZ
);
CREATE INDEX idx_tx_user ON transactions(user_id, created_at DESC);

-- 030_create_org_sso_connections.up.sql
CREATE TABLE org_sso_connections (
  id                      TEXT PRIMARY KEY NOT NULL,
  org_id                  TEXT NOT NULL REFERENCES organizations(id),
  type                    TEXT NOT NULL CHECK (type IN ('saml', 'oidc')),
  config                  JSONB NOT NULL DEFAULT '{}',    -- SAML: metadata_url, entity_id, cert_pem. OIDC: issuer, client_id
  client_secret_encrypted BYTEA,                          -- OIDC client_secret (AES-GCM per-project DEK). JSONB'de binary olmaz, ayri kolon
  enabled                 BOOLEAN NOT NULL DEFAULT true,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_sso_org ON org_sso_connections(org_id) WHERE enabled = true;

-- 031_create_scim_tokens.up.sql
CREATE TABLE scim_tokens (
  id          TEXT PRIMARY KEY NOT NULL,
  org_id      TEXT NOT NULL REFERENCES organizations(id),
  token_hash  BYTEA NOT NULL UNIQUE,
  name        TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at  TIMESTAMPTZ
);

-- 032_create_service_accounts.up.sql (PCI DSS v4.0.1 §8.6.1-8.6.3)
CREATE TABLE service_accounts (
  id                      TEXT PRIMARY KEY NOT NULL,
  project_id              TEXT NOT NULL REFERENCES projects(id),
  org_id                  TEXT REFERENCES organizations(id),
  name                    TEXT NOT NULL,
  client_id               TEXT NOT NULL UNIQUE,
  client_secret_hash      BYTEA NOT NULL,
  scopes                  JSONB NOT NULL DEFAULT '[]',    -- ["read:users", "write:users"]
  interactive_login       BOOLEAN NOT NULL DEFAULT false,  -- PCI DSS 8.6.1: default disabled
  credential_ttl_days     INTEGER,                         -- PCI DSS 8.6.3: max credential lifetime
  last_rotated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  next_rotation_at        TIMESTAMPTZ,                     -- TRA-based rotation schedule
  created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at              TIMESTAMPTZ
);

-- 033_create_personal_access_tokens.up.sql
CREATE TABLE personal_access_tokens (
  id          TEXT PRIMARY KEY NOT NULL,
  user_id     TEXT NOT NULL REFERENCES users(id),
  project_id  TEXT NOT NULL REFERENCES projects(id),
  name        TEXT NOT NULL,
  token_hash  BYTEA NOT NULL UNIQUE,
  scopes      JSONB NOT NULL DEFAULT '[]',
  expires_at  TIMESTAMPTZ NOT NULL,            -- max 1 yil
  last_used   TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at  TIMESTAMPTZ
);
CREATE INDEX idx_pat_user ON personal_access_tokens(user_id) WHERE revoked_at IS NULL;

-- 034_create_scoped_api_keys.up.sql
-- Faz 0'daki api_keys tablosu project-level auth (pk/sk). Bu tablo user/org-scoped granular keys.
CREATE TABLE scoped_api_keys (
  id          TEXT PRIMARY KEY NOT NULL,
  project_id  TEXT NOT NULL REFERENCES projects(id),
  user_id     TEXT REFERENCES users(id),          -- NULL = org-scoped
  org_id      TEXT REFERENCES organizations(id),  -- NULL = user-scoped
  name        TEXT NOT NULL,
  key_hash    BYTEA NOT NULL UNIQUE,
  key_prefix  TEXT NOT NULL,                      -- ilk 8 karakter (identification)
  scopes      JSONB NOT NULL DEFAULT '[]',        -- ["read:users", "write:users"]
  last_used   TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at  TIMESTAMPTZ
);
CREATE INDEX idx_sak_hash ON scoped_api_keys(key_hash) WHERE revoked_at IS NULL;

-- user_consents tablosu Faz 0'da olusturuldu (011). Bu fazda CREATE TABLE YOK, sadece CRUD endpoint'ler eklenir.

-- 035_create_breach_checks.up.sql
CREATE TABLE breach_checks (
  id          TEXT PRIMARY KEY NOT NULL,
  user_id     TEXT NOT NULL REFERENCES users(id),
  check_type  TEXT NOT NULL CHECK (check_type IN ('hibp', 'dark_web', 'stuffing')),
  result      TEXT NOT NULL CHECK (result IN ('clean', 'breached', 'forced_reset')),
  details     JSONB,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_breach_user ON breach_checks(user_id, created_at DESC);
```

---

## T3.1 — DPoP + PAR + FAPI 2.0

**Ne:** Sender-constrained token'lar. Token calintisini onler. FAPI 2.0 Security Profile tam uyum.

**Yapilacaklar:**
- `internal/dpop/service.go` — `AxisCommunications/go-dpop` ile:
  - `ValidateProof(proof string, method, url string) (*DPoPClaims, error)`:
    1. DPoP proof JWT parse et
    2. `typ: "dpop+jwt"` kontrol
    3. `htm` (HTTP method) + `htu` (URL) eslesmesi kontrol
    4. `jti` uniqueness (replay koruması — Redis'te)
    5. `iat` freshness (max 5dk eski)
    6. Proof signature dogrula (ES256 public key ile)
    7. Public key thumbprint (JWK Thumbprint, RFC 7638) hesapla
  - `BindToken(accessToken, proofJWK)`: Access token'a `cnf.jkt` claim'i ekle
  - `VerifyBinding(accessToken, proof)`: Token'daki `cnf.jkt` ile proof'taki key eslesiyor mu

- `internal/par/handler.go` — Pushed Authorization Requests:
  - `POST /oauth/par`:
    1. Client authentication (client_secret_basic veya private_key_jwt)
    2. Authorization request parametrelerini al (client tarafindan, redirect oncesi)
    3. `request_uri` uret, Redis'te sakla
    4. **Expiry: 600 saniye altinda** (FAPI 2.0 Sec 5.3.2.2 — SHALL)
    5. Client `request_uri` ile `/oauth/authorize`'a redirect
  - PAR kullanildiginda authorization endpoint'te parametreler request_uri'den okunur

- `internal/fapi/profile.go` — FAPI 2.0 modu (project config ile aktiflestirilir):
  - **Algoritmalar**: Sadece PS256, ES256, EdDSA. RS256 YASAK
  - **Auth code omru**: Max 60 saniye (Sec 5.3.2.1)
  - **PAR zorunlu**
  - **PKCE S256 zorunlu**
  - **Sadece confidential client** (public client YASAK)
  - **HTTP 307 redirect YASAK** (sadece 303)
  - **RFC 9207 issuer identification** (`iss` parameter donmeli)
  - **Sender-constrained token zorunlu** (DPoP veya mTLS)
  - **Refresh token rotation: SHALL NOT** — sender-constraining ile guvenlik saglenir. FAPI modunda rotation devre disi, token DPoP ile korunur
  - Token lifetime: Varsayilan 5dk (configurable ama kisa tutulmali)

**Faz 0-2'de degisen kodlar:**
- `internal/token/jwt.go` → `cnf.jkt` claim ekleme (DPoP bound token)
- `internal/token/refresh.go` → FAPI modunda rotation devre disi
- `internal/oidc/provider.go` → PAR endpoint + FAPI profil kontrolleri
- `internal/server/middleware.go` → DPoP proof dogrulama middleware

**Endpoint'ler:**
```
POST /oauth/par → { client_id, response_type, scope, ... } → { request_uri, expires_in }
```
(Diger OIDC endpoint'leri Faz 2'den mevcut, FAPI profil kontrolleri eklenir)

**Kabul kriterleri:**
- [ ] DPoP proof dogrulama calisiyor (ES256 imza)
- [ ] DPoP bound access token: `cnf.jkt` claim'i var
- [ ] DPoP replay koruması: Ayni `jti` tekrar kullanilamaz
- [ ] DPoP freshness: 5dk'dan eski proof reddedilir
- [ ] PAR endpoint calisiyor: request_uri donuyor
- [ ] PAR request_uri 600sn'den once expire oluyor
- [ ] FAPI modunda RS256 reddedilir (PS256/ES256/EdDSA only)
- [ ] FAPI modunda auth code max 60sn
- [ ] FAPI modunda public client reddedilir
- [ ] FAPI modunda HTTP 307 redirect donmez (303 kullanilir)
- [ ] FAPI modunda `iss` parameter authorization response'da var
- [ ] FAPI modunda refresh token rotation devre disi
- [ ] FAPI modunda bearer-only token reddedilir (DPoP zorunlu)
- [ ] FAPI 2.0 conformance test suite geciyor (hedef)

**Bagimlilk:** Faz 2 (OIDC Provider, token service)

---

## T3.2 — Device Attestation

**Ne:** Request'in gercek fiziksel cihazdan geldigini dogrula. Emulator/root/jailbreak tespiti.

**Yapilacaklar:**
- `internal/device/attestation.go` — Attestation service:
  - `VerifyAndroid(verdictToken string) (*AttestationResult, error)`:
    1. Encrypted verdict token'i Google Play Integrity API'ye gonder
    2. Decrypted verdict al
    3. `deviceIntegrity.deviceRecognitionVerdict` kontrol:
       - `MEETS_STRONG_INTEGRITY` → tam guven
       - `MEETS_DEVICE_INTEGRITY` → yuksek guven
       - `MEETS_BASIC_INTEGRITY` → orta guven (bootloader acik olabilir)
       - `MEETS_VIRTUAL_INTEGRITY` → emulator (finansal islemlerde red)
       - Bos → root/hook/sahte → red
    4. `appIntegrity.appRecognitionVerdict` → uygulamanin Play Store'dan yuklendigini dogrula
    5. `recentDeviceActivity.deviceActivityLevel` → abuse tespiti
    6. Sonucu `devices` tablosuna kaydet
  - `VerifyiOS(attestationObject []byte) (*AttestationResult, error)`:
    1. CBOR decode (fxamacker/cbor)
    2. x5c sertifika zinciri → Apple App Attest Root CA dogrula
    3. Nonce dogrulama: SHA256(authData + SHA256(challenge))
    4. Public key hash = keyId kontrolu
    5. rpIdHash = SHA256(teamID + "." + bundleID) kontrolu
    6. signCount = 0 kontrolu (ilk attestation)
    7. aaguid kontrolu (prod: "appattest" + 0x00*9, dev: "appattestdevelop")
    8. Public key → `devices` tablosuna kaydet
  - `VerifyAssertion(deviceID string, payload, signature []byte) (bool, error)`:
    1. Stored public key ile signature dogrula
    2. signCount artisini kontrol (clone detection)

- `internal/device/binding.go` — Cryptographic device binding:
  - `Enroll(userID string, platformAttestationResult)`:
    1. Cihaz hardware enclave'de key pair uretmis (client tarafinda)
    2. Platform attestation ile key'in gercek donanim icinde uretildigi kanitlanmis
    3. Public key + device metadata → DB'ye kaydet, user'a bagla
  - `VerifyRequest(deviceID, payload, signature)`:
    1. Stored public key ile request payload imzasini dogrula
    2. Device attestation status kontrol (verified mi?)

- Risk engine entegrasyonu: Device attestation sonucu → risk signal

**Endpoint'ler:**
```
POST /auth/devices/attest/android → { verdict_token } → { device_id, attestation_status }
POST /auth/devices/attest/ios     → { attestation_object, key_id, challenge } → { device_id, attestation_status }
POST /auth/devices/bind           → { device_id, public_key, platform_attestation } → { success }
GET  /auth/devices                → kullanicinin kayitli cihazlari
DELETE /auth/devices/:id          → cihaz kaydi sil
POST /auth/devices/:id/verify     → { payload, signature } → request dogrulama
```

**Audit event'ler:** `device.attest.android`, `device.attest.ios`, `device.bind`, `device.revoke`, `device.clone_detected`

**Kabul kriterleri:**
- [ ] Android Play Integrity: verdict token decrypt + dogrulama calisiyor
- [ ] Android: `MEETS_DEVICE_INTEGRITY` → verified, bos → rejected
- [ ] Android: Emulator (`MEETS_VIRTUAL_INTEGRITY`) → finansal islemlerde red
- [ ] iOS App Attest: 9-adim attestation dogrulama calisiyor (CBOR, x5c chain, nonce, rpIdHash, signCount, aaguid)
- [ ] iOS Assertion: request signing + signCount kontrol calisiyor
- [ ] Device binding: public key → user binding calisiyor
- [ ] Request signature dogrulama calisiyor
- [ ] Clone detection: signCount regression → alert
- [ ] Risk engine'e device attestation sinyal gidiyor
- [ ] Cihaz listesi goruntulenebiliyor + silinebiliyor

**Bagimlilk:** Faz 2 (risk engine — sinyal entegrasyonu)

---

## T3.3 — Transaction Authorization (PSD2 SCA Dynamic Linking)

**Ne:** Finansal islem onayi. Tutar + alici → challenge → TEE imza → dogrulama. WYSIWYS.

**Yapilacaklar:**
- `internal/transaction/service.go`:
  - `Create(userID, amount, currency, payeeID, payeeName) (*Transaction, error)`:
    1. Challenge olustur: `server_nonce || amount || payee_id || timestamp`
    2. Challenge hash: SHA-256
    3. `transactions` tablosuna kaydet (status=pending, expires_at=now()+5dk)
    4. Client'a challenge + transaction detaylari don (WYSIWYS icin)
  - `Approve(transactionID, deviceSignature) (*ApprovalToken, error)`:
    1. Transaction'i al, expire kontrolu (max 5dk — PSD2 RTS)
    2. `before.transaction.approve` blocking hook cagir → backend onay/red
    3. Device attestation status kontrol (verified device zorunlu)
    4. Device binding public key ile signature dogrula
    5. Signature'in challenge hash'ine spesifik oldugunu dogrula
    6. Basarili → status=approved, signed approval token don (transaction hash iceren JWT)
    7. Tutar veya alici degismisse → imza gecersiz (Dynamic linking — RTS Art. 5)
  - `Deny(transactionID, reason) error` → status=denied

- SCA exemption engine (`internal/transaction/exemption.go`):
  - Low-value: < EUR 30 (cumulative limit kontrol)
  - Recurring: Ayni tutar + alici (ilk SCA sonrasi)
  - Trusted beneficiary: Kullanici whitelistlemis
  - TRA: Fraud rate bazli exemption

**Endpoint'ler:**
```
POST /auth/transactions                 → { amount, currency, payee_id, payee_name } → { transaction_id, challenge }
POST /auth/transactions/:id/approve     → { device_signature } → { approval_token }
POST /auth/transactions/:id/deny        → { reason } → { success }
GET  /auth/transactions/:id             → transaction detay + status
GET  /auth/transactions                 → kullanicinin transaction gecmisi
```

**Audit event'ler:** `transaction.create`, `transaction.approve`, `transaction.deny`, `transaction.expire`

**Kabul kriterleri:**
- [ ] Transaction challenge olusturuluyor (nonce + amount + payee)
- [ ] Challenge 5dk sonra expire oluyor (PSD2 RTS)
- [ ] WYSIWYS: Client tutar + alici bilgisini goruyor
- [ ] Device signature dogrulamasi calisiyor
- [ ] Dynamic linking: Tutar degisirse imza gecersiz
- [ ] Dynamic linking: Alici degisirse imza gecersiz
- [ ] `before.transaction.approve` hook cagrilir
- [ ] Device attestation verified olmayan cihaz reddedilir
- [ ] Approval token transaction hash iceriyor
- [ ] SCA exemption: Low-value (< EUR 30) calisiyor
- [ ] SCA exemption: Recurring calisiyor (ilk SCA sonrasi)
- [ ] Max 5 basarisiz deneme → transaction lockout 30dk (PSD2 RTS max 5 failed + PCI DSS 8.3.4 30dk lockout)

**Bagimlilk:** T3.2 (device attestation + binding), Faz 1 (hooks)

---

## T3.4 — SAML 2.0 (SP + IdP)

**Ne:** SAML SP (harici IdP'lerden identity kabul) + SAML IdP (SAML ile entegrasyon isteyenler icin). XXE koruması.

**Yapilacaklar:**
- `internal/saml/sp.go` — Service Provider (`crewjam/saml` v0.5.1):
  - SAML Assertion parsing ve dogrulama
  - XML Signature Verification (XML DSig)
  - Assertion encryption destegi (AES-256)
  - NameID format: emailAddress, persistent, transient
  - Single Logout (SLO)
  - Metadata endpoint: `GET /.well-known/saml-metadata.xml`
  - Per-org SSO connection: Org admin SAML metadata upload → otomatik SP config

- `internal/saml/idp.go` — Identity Provider:
  - SAML Response/Assertion uretimi
  - SP metadata import
  - Attribute mapping (SAML attributes → user claims)
  - Per-project IdP config

- `internal/saml/security.go`:
  - XXE koruması: `encoding/xml` external entity resolution KAPALI (Go default — ama explicit kontrol)
  - DTD processing KAPALI
  - XML bomb koruması: max entity depth + max document size (1MB)
  - crewjam/saml v0.5.1: CVE-2022-41912 ve CVE-2023-45683 fixli

- `internal/saml/piv.go` — PIV/CAC hazirlik (FedRAMP High icin):
  - SAML SP olarak PIV-aware IdP'den identity kabul (ICAM, kurum-owned IdP)
  - X.509 client sertifika dogrulama mekanizmasi (mTLS endpoint)
  - OCSP/CRL ile sertifika gecerlilik kontrolu

**Enterprise SSO per org:**
- `internal/org/sso.go`:
  - Org admin SAML metadata URL girer veya XML upload eder
  - Otomatik SP config olusturulur
  - OIDC SSO: Org admin OIDC issuer URL girer → auto-discovery
  - Self-service setup UI (Dashboard'dan)
  - JIT (Just-in-Time) user provisioning: IdP'den gelen kullanici otomatik olusturulur

**Endpoint'ler:**
```
GET  /.well-known/saml-metadata.xml           → SP metadata
POST /auth/saml/:connection_id/acs            → Assertion Consumer Service
GET  /auth/saml/:connection_id/login          → SP-initiated login redirect
POST /auth/saml/:connection_id/slo            → Single Logout
POST /auth/saml/idp/sso                       → IdP SSO endpoint
GET  /auth/saml/idp/metadata                  → IdP metadata

POST   /admin/projects/:id/organizations/:oid/sso → { type: "saml"|"oidc", config } → SSO connection
GET    /admin/projects/:id/organizations/:oid/sso → SSO connections listesi
PUT    /admin/projects/:id/organizations/:oid/sso/:sid → SSO connection guncelle
DELETE /admin/projects/:id/organizations/:oid/sso/:sid → SSO connection sil
```

**Kabul kriterleri:**
- [ ] SAML SP: IdP'den login calisiyor (end-to-end)
- [ ] SAML SP: Assertion signature dogrulamasi calisiyor
- [ ] SAML SP: Assertion encryption calisiyor
- [ ] SAML SP: SLO calisiyor
- [ ] SAML IdP: SP'ye assertion donuyor
- [ ] XXE koruması: External entity → reddedilir
- [ ] XML bomb: Buyuk XML → reddedilir (max 1MB)
- [ ] Per-org SSO: SAML metadata upload → otomatik config
- [ ] Per-org SSO: OIDC auto-discovery calisiyor
- [ ] JIT provisioning: IdP'den gelen yeni kullanici otomatik olusur
- [ ] PIV/CAC: X.509 client cert dogrulama mekanizmasi hazir

**Bagimlilk:** Faz 2 (organizations), Faz 0 (auth, session)

---

## T3.5 — SCIM 2.0 Provisioning

**Ne:** Per-org SCIM endpoint. Harici IdP'lerden (Okta, Azure AD) otomatik kullanici ekleme/cikarma.

**Yapilacaklar:**
- `internal/scim/server.go` — `elimity-com/scim` ile:
  - `/scim/v2/Users` — CRUD (POST, GET, PUT, PATCH, DELETE)
  - `/scim/v2/Groups` — CRUD
  - `/scim/v2/ServiceProviderConfig` — SCIM config
  - `/scim/v2/Schemas` — schema bilgisi
  - Per-org SCIM token authentication (bearer token per org)
  - User create → PalAuth user + org member olustur
  - User delete → PalAuth user deactivate (org'dan cikar)
  - User update → PalAuth user metadata guncelle

**Endpoint'ler:**
```
GET    /scim/v2/Users                → kullanici listesi (org-scoped)
POST   /scim/v2/Users                → kullanici olustur
GET    /scim/v2/Users/:id            → kullanici detay
PUT    /scim/v2/Users/:id            → kullanici guncelle (tam)
PATCH  /scim/v2/Users/:id            → kullanici guncelle (kismi)
DELETE /scim/v2/Users/:id            → kullanici deactivate
GET    /scim/v2/Groups               → grup listesi
POST   /scim/v2/Groups               → grup olustur
GET    /scim/v2/ServiceProviderConfig → SCIM config
GET    /scim/v2/Schemas               → schema
```

**Kabul kriterleri:**
- [ ] SCIM User CRUD calisiyor (Okta SCIM test suite ile dogrulanir)
- [ ] SCIM Group CRUD calisiyor
- [ ] Per-org bearer token authentication calisiyor
- [ ] User create → PalAuth user + org member
- [ ] User delete → user deactivate
- [ ] Azure AD SCIM entegrasyonu calisiyor
- [ ] Okta SCIM entegrasyonu calisiyor

**Bagimlilk:** Faz 2 (organizations)

---

## T3.6 — API Keys (Scoped) + M2M + PATs + Service Accounts

**Ne:** Granular API key'ler, M2M client_credentials flow, Personal Access Tokens, PCI DSS 8.6.x uyumlu service accounts.

**Yapilacaklar:**
- `internal/apikey/scoped.go` — Scoped API key'ler (Faz 0'daki project key'lerden farkli):
  - User veya org-scoped
  - Granular permission scope'lari: `read:users`, `write:users`, `admin:*`
  - SHA-256 hash, revocable, rate limit per key

- `internal/m2m/service.go` — Machine-to-Machine:
  - OAuth 2.0 `client_credentials` flow (Faz 2 OIDC Provider'a eklenir)
  - Client ID + Client Secret → kisa omurlu JWT (org-scoped, `org_id` claim)
  - Service account tablosu ile yonetilir

- `internal/pat/service.go` — Personal Access Tokens:
  - Kullanici kendi token'ini olusturur
  - Scope secimi, max 1 yil expiry
  - SHA-256 hash, revocable
  - Kullanicinin kendi yetkileri ile sinirli

- `internal/serviceaccount/service.go` — PCI DSS v4.0.1 §8.6.1-8.6.3:
  - Her service account benzersiz ID (paylasimli YASAK — §8.6.1)
  - `interactive_login = false` default (§8.6.1)
  - Hard-coded credential YASAK — credential'lar DB'de, runtime inject (§8.6.2)
  - Credential rotation: configurable TTL, TRA-based (§8.6.3)
  - Rotation API: yeni credential uret, eski grace period sonra gecersiz (zero-downtime)
  - Credential lifecycle tamamen loglanir (olusturma, rotation, iptal)

**Endpoint'ler:**
```
POST   /admin/projects/:id/api-keys       → { name, scopes, org_id? } → { key (tek seferlik), key_id }
GET    /admin/projects/:id/api-keys       → key listesi
DELETE /admin/projects/:id/api-keys/:kid  → key revoke

POST   /admin/projects/:id/service-accounts          → { name, scopes, org_id?, credential_ttl_days? }
GET    /admin/projects/:id/service-accounts
POST   /admin/projects/:id/service-accounts/:said/rotate → credential rotation (grace period ile)
DELETE /admin/projects/:id/service-accounts/:said     → revoke

POST   /oauth/token (grant_type=client_credentials)   → M2M JWT

POST   /auth/tokens/personal   → { name, scopes, expires_in } → { token (tek seferlik) }
GET    /auth/tokens/personal   → PAT listesi
DELETE /auth/tokens/personal/:id → PAT revoke
```

**Audit event'ler:** `apikey.create`, `apikey.revoke`, `serviceaccount.create`, `serviceaccount.rotate`, `serviceaccount.revoke`, `pat.create`, `pat.revoke`, `m2m.token.issue`

**Kabul kriterleri:**
- [ ] Scoped API key: scope'lu erisim calisiyor (yetkisiz scope → 403)
- [ ] M2M client_credentials → JWT donuyor (org-scoped)
- [ ] PAT: User kendi token'ini olusturabiliyor, scope sinirli
- [ ] PAT: Max 1 yil expiry
- [ ] Service account: Benzersiz ID, paylasimli degil
- [ ] Service account: interactive_login default false
- [ ] Service account: Credential rotation calisiyor (grace period ile zero-downtime)
- [ ] Service account: Credential TTL calisiyor (expire → otomatik deactivate)
- [ ] Service account: Lifecycle tamamen audit logda
- [ ] Hard-coded credential kontrolu: Config'de plain secret → uyari

**Bagimlilk:** Faz 2 (OIDC Provider — client_credentials grant, organizations)

---

## T3.7 — GDPR DSAR + Breach Detection

**Ne:** GDPR Data Subject Access Requests (export, delete, consent) + HIBP monitoring + credential monitoring.

**Yapilacaklar:**
- `internal/compliance/dsar.go`:
  - `Export(userID)`: Kullanicinin tum verisini JSON olarak export (GDPR Art. 20)
    - User profil, identities, sessions, MFA enrollments, devices, consents, audit log (decrypted PII)
  - `Delete(userID)`: Faz 0'daki GDPR erasure akisi + ek:
    - Social identities sil
    - MFA enrollments sil
    - Devices sil
    - Consents sil
    - Recovery codes sil
    - PATs revoke
    - `gdpr.erasure` audit event (zaten Faz 0'da)
  - `Consent CRUD`: Purpose-based consent kaydi (marketing, analytics, third_party_sharing)
    - Consent version tracking
    - Consent verme = geri cekme kadar kolay olmali (GDPR Art. 7)

- `internal/breach/hibp.go`:
  - Periyodik kontrol: Tum kullanicilarin email'lerini HIBP API ile kontrol (k-Anonymity)
  - Cron: Haftalik calisir
  - Etkilenen kullanicilar icin:
    - Zorunlu sifre degisikligi (next login'de force reset)
    - Bildirim email'i
    - Admin alert
    - `breach.detected` audit event

- `internal/breach/monitoring.go`:
  - Pluggable connector interface (Faz 4+ icin BreachSense, SpyCloud):
    ```go
    type BreachMonitor interface {
      Check(ctx context.Context, email string) (*BreachResult, error)
    }
    ```
  - Built-in: HIBP. Connector: Faz 4+'de genisletilebilir

- Data retention (`internal/compliance/retention.go`):
  - Project config: retention_days (default: 365 — SOC 2 minimum 12 ay)
  - Cron: Gunluk calisir, suresi dolan verileri temizler (encryption key silme ile)
  - Audit loglar: retention suresi dolunca cold storage'a tasinir (veya silinir)

**Endpoint'ler:**
```
GET    /admin/projects/:id/users/:uid/export   → JSON export (GDPR Art. 20)
DELETE /admin/projects/:id/users/:uid          → GDPR erasure (zaten Faz 0'da, genisletildi)
GET    /admin/projects/:id/users/:uid/consents → consent gecmisi
POST   /admin/projects/:id/users/:uid/consents → { purpose, granted, version } → consent kaydi
PUT    /admin/projects/:id/users/:uid/consents/:cid/revoke → consent geri cek

GET    /admin/projects/:id/breach-status       → son breach check sonuclari
POST   /admin/projects/:id/breach-check        → manuel breach check tetikle
```

**Audit event'ler:** `gdpr.export`, `gdpr.erasure` (Faz 0'dan), `gdpr.consent.grant`, `gdpr.consent.revoke`, `breach.detected`, `breach.forced_reset`, `retention.purge`

**Kabul kriterleri:**
- [ ] GDPR export: Kullanicinin tum verisi JSON olarak indirilebiliyor
- [ ] GDPR delete: Tum user verisi + iliskili veriler siliniyor + cryptographic erasure
- [ ] Consent CRUD calisiyor (purpose, version, granted/revoked)
- [ ] Consent geri cekme kolayligi (verme kadar kolay — GDPR Art. 7)
- [ ] HIBP kontrol calisiyor (haftalik cron)
- [ ] Breached kullaniciya zorunlu sifre degisikligi uygulanir
- [ ] Data retention: Suresi dolan veriler otomatik temizlenir
- [ ] Breach monitor pluggable interface calisiyor

**Bagimlilk:** Faz 0 (GDPR erasure, audit), Faz 1 (email — bildirimler)

---

## T3.8 — Dashboard Genisletme + Test Sweep

**Ne:** Dashboard'a SSO konfig, device attestation, compliance paneli ekle. FAPI 2.0 + SAML test.

**Yapilacaklar:**
- Project detail → **Organizations genisletme:**
  - SSO connection CRUD (SAML metadata upload, OIDC discovery URL)
  - SSO test butonu
  - SCIM endpoint durumu + token yonetimi
- Project detail → **Security genisletme:**
  - Device attestation sonuclari (verified/failed/revoked per device)
  - Transaction gecmisi (approved/denied/expired)
- Project detail → **Compliance (yeni sayfa):**
  - GDPR DSAR islem paneli (export, delete istekleri)
  - Consent yonetimi
  - Breach detection durumu (son check, etkilenen kullanicilar)
  - Data retention config
  - Service account credential durumu (son rotation, sonraki rotation)
- Project detail → **API Keys genisletme:**
  - Scoped API key'ler + M2M service accounts + PATs
  - Credential rotation UI

**Test sweep:**
- Integration testler:
  - DPoP flow: Token issue → DPoP proof → resource access
  - FAPI 2.0: PAR → authorize → token (FAPI profile kontrolleri)
  - Device attestation: Android + iOS mock attestation → verify
  - Transaction: Create → approve (device signature) → approval token
  - Dynamic linking: Amount/payee degisimi → imza gecersiz
  - SAML SP: IdP'den login (end-to-end)
  - SCIM: User create/update/delete (Okta test suite)
  - M2M: client_credentials → JWT
  - GDPR: Export → delete → audit log chain intact
  - Breach: HIBP check → forced reset
- Security testler:
  - FAPI 2.0 conformance suite
  - DPoP replay koruması
  - PAR request_uri expiry
  - SAML XXE koruması
  - Transaction signature manipulation → reject
- Coverage: %85+ (guvenlik modulleri %90+)

**Ek test katmanlari:**
- DAST: ZAP — DPoP, PAR, SAML, SCIM, transaction endpoint'leri
- Mutation: `internal/dpop/*`, `internal/transaction/*`, `internal/saml/*` icin gremlins
- Load: k6 DPoP-bound token flow p99 < 500ms, transaction approve p99 < 1s
- Chaos: QTSP API down → transaction flow graceful failure
- Conformance: FAPI 2.0 Security Profile suite

**Kabul kriterleri:**
- [ ] Dashboard SSO konfig calisiyor
- [ ] Dashboard device attestation gorunuyor
- [ ] Dashboard compliance paneli calisiyor
- [ ] Tum integration testler geciyor
- [ ] FAPI 2.0 conformance hedefine yaklasiliyor
- [ ] Coverage %85+
- [ ] DAST: SAML XXE testi PASS
- [ ] Mutation score: DPoP + transaction modulleri %80+
- [ ] k6 load: DPoP flow p99 < 500ms

**Bagimlilk:** T3.1-T3.7

---

## Yeni Audit Event'ler (Faz 3 Eklenen)

| Event | Tetikleme |
|-------|-----------|
| `dpop.bind` | DPoP token binding |
| `dpop.verify.failure` | DPoP proof dogrulama basarisiz |
| `par.request` | PAR request |
| `device.attest.android` | Android attestation |
| `device.attest.ios` | iOS attestation |
| `device.bind` | Device binding |
| `device.revoke` | Device revoke |
| `transaction.create` | Transaction olusturuldu |
| `transaction.approve` | Transaction onaylandi |
| `transaction.deny` | Transaction reddedildi |
| `transaction.expire` | Transaction suresi doldu |
| `saml.login` | SAML ile login |
| `saml.logout` | SAML SLO |
| `sso.connect` | Org SSO connection olusturuldu |
| `scim.user.create` | SCIM ile user olusturuldu |
| `scim.user.update` | SCIM ile user guncellendi |
| `scim.user.delete` | SCIM ile user deactivate |
| `apikey.create/revoke` | API key lifecycle |
| `serviceaccount.*` | Service account lifecycle |
| `pat.create/revoke` | PAT lifecycle |
| `m2m.token.issue` | M2M token verildi |
| `gdpr.export` | GDPR data export |
| `gdpr.consent.*` | Consent grant/revoke |
| `breach.detected` | Breach tespit |
| `breach.forced_reset` | Zorunlu sifre degisikligi |
| `retention.purge` | Data retention temizligi |

---

## Haftalik Plan (24 hafta — Ay 11-16)

| Hafta | Task'lar | Not |
|-------|----------|-----|
| 1-3 | T3.1 (DPoP + PAR + FAPI 2.0 profile) | Financial-grade token security |
| 4-6 | T3.2 (Device attestation — Play Integrity, App Attest, binding) | Device security |
| 7-9 | T3.3 (Transaction authorization — PSD2 SCA, dynamic linking, WYSIWYS, exemptions) | Payment security |
| 10-14 | T3.4 (SAML 2.0 — SP + IdP + XXE + per-org SSO + JIT provisioning + PIV/CAC) | En uzun task — SAML karmasik |
| 15-16 | T3.5 (SCIM 2.0 — per-org endpoint, Okta/Azure AD test) | Enterprise provisioning |
| 17-19 | T3.6 (API keys + M2M + PATs + service accounts — PCI DSS 8.6.x) | Non-human auth |
| 20-22 | T3.7 (GDPR DSAR + breach detection + data retention) | Compliance automation |
| 23-24 | T3.8 (Dashboard + FAPI conformance + test sweep) | Final |

**Not:** Her task kendi testini birlikte yazar. T3.8 final sweep + FAPI conformance.
