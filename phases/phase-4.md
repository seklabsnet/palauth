# PalAuth — Faz 4: Scale + Compliance + SaaS Baslangic (Ay 17-22)

> Hedef: SOC 2 Type II raporu alma. Multi-region. Admin impersonation. SaaS katmani baslar.
> Faz 0+1+2+3 uzerine insa.
> Paketler: `caddyserver/certmagic`, `go.opentelemetry.io/otel`

---

## Yeni DB Migration'lar

```sql
-- 036_create_trusted_contacts.up.sql (spec Section 11.1.2 — N-of-M recovery)
CREATE TABLE trusted_contacts (
  id              TEXT PRIMARY KEY NOT NULL,
  user_id         TEXT NOT NULL REFERENCES users(id),
  contact_email   TEXT NOT NULL,
  contact_name    TEXT,
  verification_token_hash BYTEA,
  verified        BOOLEAN NOT NULL DEFAULT false,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_tc_user ON trusted_contacts(user_id);

-- 037_create_recovery_requests.up.sql
CREATE TABLE recovery_requests (
  id              TEXT PRIMARY KEY NOT NULL,
  user_id         TEXT NOT NULL REFERENCES users(id),
  method          TEXT NOT NULL CHECK (method IN ('recovery_code', 'trusted_contacts', 'recovery_passkey', 'admin_assisted')),
  required_approvals INTEGER,           -- trusted contacts icin: M (ornek: 2/3)
  current_approvals  INTEGER NOT NULL DEFAULT 0,
  status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at      TIMESTAMPTZ NOT NULL  -- 72 saat
);

-- 038_create_recovery_approvals.up.sql
CREATE TABLE recovery_approvals (
  id              TEXT PRIMARY KEY NOT NULL,
  recovery_request_id TEXT NOT NULL REFERENCES recovery_requests(id),
  contact_id      TEXT NOT NULL REFERENCES trusted_contacts(id),
  token_hash      BYTEA NOT NULL UNIQUE,
  approved        BOOLEAN,
  approved_at     TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at      TIMESTAMPTZ NOT NULL
);

-- 039_create_custom_domains.up.sql
CREATE TABLE custom_domains (
  id          TEXT PRIMARY KEY NOT NULL,
  project_id  TEXT NOT NULL REFERENCES projects(id),
  domain      TEXT NOT NULL UNIQUE,
  tls_status  TEXT NOT NULL DEFAULT 'pending' CHECK (tls_status IN ('pending', 'provisioning', 'active', 'failed', 'expired')),
  cert_expires_at TIMESTAMPTZ,
  verified    BOOLEAN NOT NULL DEFAULT false,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 040_create_migration_jobs.up.sql (Auth0/Firebase/Supabase/Clerk import)
CREATE TABLE migration_jobs (
  id          TEXT PRIMARY KEY NOT NULL,
  project_id  TEXT NOT NULL REFERENCES projects(id),
  source      TEXT NOT NULL CHECK (source IN ('auth0', 'firebase', 'supabase', 'clerk', 'csv')),
  status      TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
  total_users INTEGER,
  imported    INTEGER NOT NULL DEFAULT 0,
  failed      INTEGER NOT NULL DEFAULT 0,
  error_log   JSONB,
  started_at  TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

---

## T4.1 — Admin Impersonation (RFC 8693)

**Ne:** Admin'in kullanici gibi davranmasi. Full audit trail. Hassas islem kisitlamalari.

**Yapilacaklar:**
- `internal/admin/impersonate.go`:
  - `Start(adminID, targetUserID string) (*ImpersonationToken, error)`:
    1. Admin `impersonate` iznine sahip mi kontrol et
    2. RFC 8693 Token Exchange ile impersonation JWT uret:
       ```json
       {
         "sub": "usr_target",
         "act": { "sub": "admin_123" },
         "scope": "impersonation",
         "exp": "max 1 saat"
       }
       ```
    3. `admin.impersonate.start` audit event (admin_id, target_user_id, timestamp)
    4. Target kullaniciya bildirim email (project config ile ayarlanabilir)
  - `End(impersonationTokenID string) error`:
    1. Impersonation session sonlandir
    2. `admin.impersonate.end` audit event (duration, actions_taken_count)
  - Impersonation middleware:
    - Impersonation token ile yapilan TUM islemler audit log'da `impersonated: true` flag
    - YASAKLI islemler (impersonation sirasinda):
      - Sifre degistirme
      - MFA ekleme/cikarma
      - Email degistirme
      - Hesap silme
      - Baska kullaniciyi impersonate etme

**Endpoint'ler:**
```
POST /admin/projects/:id/users/:uid/impersonate → { } → { impersonation_token, expires_at }
POST /admin/impersonation/end                    → { } → { duration, actions_count }
```

**Audit event'ler:** `admin.impersonate.start`, `admin.impersonate.end`, tum islemlerde `impersonated: true`

**Kabul kriterleri:**
- [ ] Impersonate basliyor — target user gibi davranan token donuyor
- [ ] Token'da `act.sub` = admin ID, `sub` = target user ID
- [ ] Max 1 saat, sonra expire
- [ ] Tum islemler audit logda `impersonated: true` flag ile
- [ ] Sifre degistirme impersonation'da → 403
- [ ] MFA ekleme/cikarma impersonation'da → 403
- [ ] Email degistirme impersonation'da → 403
- [ ] Impersonate iznine sahip olmayan admin → 403
- [ ] Target kullaniciya bildirim email gonderiliyor (config ile)

**Bagimlilk:** Faz 0 (admin auth, audit), Faz 1 (hooks)

---

## T4.2 — Trusted Contacts Recovery (N-of-M)

**Ne:** Spec Section 11.1.2. Kullanici 3-5 guvenilir kisi belirler, recovery icin M/N onay gerekir.

**Yapilacaklar:**
- `internal/recovery/contacts.go`:
  - `AddContact(userID, contactEmail, contactName)`:
    1. Contact'a verification email gonder
    2. Contact dogrulama token'i olustur
    3. Contact onaylarsa `verified = true`
    4. Max 5 contact per user
  - `RemoveContact(userID, contactID)`
  - `InitiateRecovery(userID string) (*RecoveryRequest, error)`:
    1. Kullanicinin verified contact'larini bul
    2. Recovery request olustur (required_approvals = ceil(contacts/2), orn 3 contact → 2 onay)
    3. Her contact'a approval email gonder (unique token)
    4. Request 72 saat gecerli
  - `ApproveRecovery(token string) error`:
    1. Token dogrula (hash, expiry)
    2. `current_approvals++`
    3. Yeterli onay toplandiysa → recovery basarili
    4. Recovery basarili:
       - Tum session'lar sonlandirilir (spec Section 11.2)
       - Yeni MFA enrollment zorunlu (spec Section 11.2)
       - Gecici magic link veya sifre gonderilir
       - `recovery.complete` audit event

**Endpoint'ler:**
```
GET    /auth/recovery/contacts       → contact listesi
POST   /auth/recovery/contacts       → { email, name } → contact ekle
DELETE /auth/recovery/contacts/:id   → contact cikar
POST   /auth/recovery/contacts/:id/verify → { token } → contact dogrula
POST   /auth/recovery/initiate       → { } → recovery baslatir
POST   /auth/recovery/approve        → { token } → contact onayi
GET    /auth/recovery/status         → { pending_approvals, required, current }
```

**Audit event'ler:** `recovery.contact.add`, `recovery.contact.remove`, `recovery.initiate`, `recovery.approve`, `recovery.complete`

**Kabul kriterleri:**
- [ ] Contact ekleme + dogrulama calisiyor
- [ ] Max 5 contact kontrolu
- [ ] Recovery baslatma → tum contact'lara email gidiyor
- [ ] N-of-M: 3 contact'tan 2 onay → recovery basarili
- [ ] Recovery sonrasi tum session'lar sonlanir
- [ ] Recovery sonrasi MFA enrollment zorunlu
- [ ] Recovery request 72 saat sonra expire

**Bagimlilk:** Faz 0 (user, email, audit), Faz 1 (recovery codes — ayni recovery framework)

---

## T4.3 — Multi-Region Data Residency

**Ne:** Kullanici verileri project'in sectigi region'da saklanir. Cross-region transfer yasak.

**Yapilacaklar:**
- `internal/region/service.go`:
  - Project config'e `region` field eklenir: `eu`, `us`, `apac`, `tr`
  - **Mimari**: Her region icin ayri PostgreSQL instance. Go server baglanti havuzunu region'a gore secer:
    ```go
    // Region-based connection routing
    func (s *RegionService) GetPool(region string) *pgxpool.Pool {
      return s.pools[region] // eu → eu-postgres, us → us-postgres, ...
    }
    ```
  - Project olusturulurken region secilir, sonra degistirilemez (migration haric)
  - Tum query'ler project'in region'indaki DB'ye gider
  - Encryption key'ler region-local KMS'te uretilir (AWS: eu-west-1 KMS, us-east-1 KMS, ...)
  - Backup'lar ayni region'da
  - Audit loglar ayni region'da
  - Cross-region query YASAK — middleware ile enforce edilir
- Project config genisletme:
  ```json
  { "region": "eu", "data_residency": { "enforce": true, "allowed_regions": ["eu"] } }
  ```
- Cross-region veri transferi kontrol middleware'i
- GDPR Art. 44-49 uyumu: SCCs veya adequacy decisions

**Kabul kriterleri:**
- [ ] Project region secebiliyor
- [ ] Veri sectigi region'da saklaniyor
- [ ] Cross-region transfer engellenebiliyor (config ile)
- [ ] KMS key'ler region-local

**Bagimlilk:** Faz 0 (project config, database)

---

## T4.4 — Custom Domain + White-Label

**Ne:** Project basina ozel domain + Let's Encrypt TLS + branding.

**Yapilacaklar:**
- `internal/domain/service.go` — `caddyserver/certmagic` ile:
  - Domain dogrulama: DNS CNAME veya TXT record
  - Otomatik TLS sertifikasi (Let's Encrypt ACME)
  - Otomatik yenileme
  - Sertifika durumu tracking (pending/active/expired)
- `internal/branding/service.go`:
  - Project bazinda branding config: logo URL, primary color, secondary color
  - Login/register sayfalari project branding ile render edilir
  - Email template'leri project branding ile
  - Hata mesajlari project diline gore

**Endpoint'ler:**
```
POST   /admin/projects/:id/domains      → { domain } → domain dogrulama baslat
GET    /admin/projects/:id/domains      → domain listesi + TLS durumu
DELETE /admin/projects/:id/domains/:did → domain kaldir
PUT    /admin/projects/:id/branding     → { logo_url, primary_color, ... }
GET    /admin/projects/:id/branding     → branding config
```

**Kabul kriterleri:**
- [ ] Custom domain ekleniyor + DNS dogrulama calisiyor
- [ ] Let's Encrypt TLS sertifikasi otomatik aliniyor
- [ ] Sertifika otomatik yenileniyor
- [ ] Branding config login sayfasina yansıyor
- [ ] Email template'ler project branding ile

**Bagimlilk:** Faz 0 (project config)

---

## T4.5 — Advanced Risk Engine + Advanced Webhooks

**Ne:** 3rd party risk connectors + webhook fan-out, DLQ genisletme.

**Yapilacaklar:**
- `internal/risk/connectors/fingerprint.go` — Fingerprint.com entegrasyonu
- `internal/risk/connectors/maxmind.go` — MaxMind GeoIP2 Insights (Faz 2'deki GeoLite2'den upgrade)
- `internal/risk/behavioral.go` — Behavioral signals: login pattern analizi, zaman dagilimi
- `internal/webhook/fanout.go` — Ayni event birden fazla endpoint'e gonderme
- `internal/webhook/delivery_log.go` — Detayli delivery log UI (request body, response body, latency)

**Kabul kriterleri:**
- [ ] Fingerprint.com connector calisiyor (pluggable)
- [ ] MaxMind Insights connector calisiyor
- [ ] Behavioral signals risk engine'e entegre
- [ ] Webhook fan-out calisiyor (1 event → N endpoint)

**Bagimlilk:** Faz 2 (risk engine), Faz 1 (webhooks)

---

## T4.6 — Migration Araclari

**Ne:** Auth0, Firebase, Supabase, Clerk'ten kullanici import. Password hash migration.

**Yapilacaklar:**
- `internal/migration/service.go`:
  - Import formatları: Auth0 JSON, Firebase JSON, Supabase CSV/JSON, Clerk, Generic CSV
  - `Import(projectID, source, file)`:
    1. Dosyayi parse et
    2. Her kullanici icin:
       - Email duplicate kontrolu
       - Password hash import (bcrypt, PBKDF2, Argon2 direkt kabul)
       - SHA-256/MD5 hash: Kullaniciya "sifrenizi yenileyin" email gonder
       - Login'de otomatik Argon2id upgrade (eski hash dogrulama + yeni hash kaydetme)
    3. Progress tracking (imported, failed, total)
    4. Error log
  - Background job (Watermill)

**Endpoint'ler:**
```
POST /admin/projects/:id/migrations      → { source, file } → migration job baslat
GET  /admin/projects/:id/migrations      → migration job listesi
GET  /admin/projects/:id/migrations/:mid → job detay (progress, errors)
```

**Kabul kriterleri:**
- [ ] Auth0 JSON import calisiyor
- [ ] Firebase JSON import calisiyor
- [ ] Generic CSV import calisiyor
- [ ] bcrypt hash'ler direkt kabul ediliyor
- [ ] SHA-256/MD5 hash → "sifre yenile" email gonderiliyor
- [ ] Login'de hash auto-upgrade calisiyor (eski hash → Argon2id)
- [ ] Progress tracking calisiyor

**Bagimlilk:** Faz 0 (user, crypto, email)

---

## T4.7 — i18n (Temel)

**Ne:** Hata mesajlari ve email template'leri icin en + tr dil destegi.

**Yapilacaklar:**
- `internal/i18n/service.go`:
  - Go embed ile dil dosyalari (`locales/en.json`, `locales/tr.json`)
  - Error mesajlari: `invalid_credentials` → EN: "Invalid email or password", TR: "Gecersiz email veya sifre"
  - Email template'leri: dil bazinda
  - Project config'den varsayilan dil secimi
  - Accept-Language header'dan dil tespiti

**Kabul kriterleri:**
- [ ] Hata mesajlari EN ve TR destekliyor
- [ ] Email template'leri EN ve TR
- [ ] Accept-Language header calisiyor
- [ ] Project default dil ayarlanabiliyor

**Bagimlilk:** Faz 0 (email templates, error responses)

---

## T4.8 — Operasyonel Prosedurler (SOC 2 / ISO 27001 Hazirlik)

**Ne:** SOC 2 Type II ve ISO 27001 sertifikasi icin gerekli operasyonel altyapi.

**Yapilacaklar:**
- `docs/compliance/`:
  - Backup & DR proseduru:
    - RPO 1 saat, RTO 4 saat
    - PostgreSQL PITR config
    - Encrypted backup (AES-256-GCM)
    - 6 aylik DR test proseduru template
  - Incident response plan:
    - Detection → Triage (P1-P4) → Containment → Eradication → Recovery → Post-mortem
    - GDPR 72 saat breach notification proseduru
    - Yillik tabletop exercise template
  - Change management:
    - PR + review + approval zorunlulugu (CODEOWNERS)
    - Staging test zorunlulugu
    - Rollback proseduru
    - Emergency change sureci
  - Vulnerability management:
    - Dependency scan (Snyk/Trivy — CI/CD'de zaten var, dokumante et)
    - DAST config (OWASP ZAP baseline)
    - Yillik pentest scope template
    - Remediation SLA: Critical=7d, High=30d, Medium=90d
  - SOC 2 evidence collection:
    - CI/CD pipeline log'lari → otomatik evidence
    - Audit log export → compliance format
    - Pen test raporu template
    - Access review template (ceyreklik)
  - ISO 27001 ISMS dokumantasyonu:
    - Information Security Policy
    - Risk Assessment methodology
    - Statement of Applicability (SoA)
  - PCI DSS Customized Approach dokumantasyonu (spec Section 2.1):
    - Password composition rules uygulanmama gerekcelendirmesi
    - NIST 800-63B tam kontrol seti kaniti (HIBP, no rotation, Argon2id)
    - Targeted Risk Analysis
    - Kontrol matrisi + yonetici onayi
    - QSA validasyonu icin hazirlik
  - Key ceremony proseduru (spec Section 17.5):
    - Split knowledge (Shamir's Secret Sharing 3-of-5)
    - Dual control (min 2 yetkili kisi)
    - Ceremony script + checklist
    - Witness + video kayit proseduru
    - Share distribution + safe storage
  - GDPR DPIA (Data Protection Impact Assessment — spec-compliance Section 7, Art. 35):
    - Deployment oncesi tamamlanmali
    - Isleme amaci, risk degerlendirmesi, risk azaltma onlemleri dokumante
  - DPF (EU-US Data Privacy Framework) self-certification (spec-compliance Section 1):
    - Transatlantic veri transferi icin
    - Self-certification proseduru + annual renewal
  - CSA STAR Level 1 self-assessment (spec-compliance Section 1 — "Day 1" ama Faz 4'te resmi):
    - CAIQ (Consensus Assessments Initiative Questionnaire) doldur
    - CSA STAR Registry'ye kayit (ucretsiz)
  - FIPS 140-3 mode implementasyonu (spec-compliance Section 9):
    - Argon2id FIPS-approved degil → FIPS modunda PBKDF2-HMAC-SHA256 (600K+ iteration)
    - Project config: `fips_mode: true` → approved-only algoritmalar enforce
    - `PALAUTH_FIPS=true` env var veya `--fips` flag
  - DORA compliance (spec-compliance Section 8):
    - DORA-compliant sozlesme template'leri (SLA, exit plan, denetim haklari)
    - ICT risk management framework dokumantasyonu
    - Incident classification + 24 saat reporting proseduru
    - TLPT (Threat-Led Penetration Testing) plani
    - Is surekliligi test raporu template (6 aylik)
    - Denetim erisim mekanizmasi (read-only audit access endpoint)

**Kabul kriterleri:**
- [ ] Backup/DR proseduru dokumante
- [ ] DR test proseduru calistirilabilir (6 aylik)
- [ ] Incident response plan dokumante
- [ ] Change management CODEOWNERS ile enforce ediliyor
- [ ] Vulnerability scan CI/CD'de otomatik calisir
- [ ] SOC 2 evidence collection otomatik
- [ ] ISO 27001 ISMS temel dokumanlar hazir

**Bagimlilk:** Tum onceki fazlar tamamlanmis

---

## T4.9 — Dashboard Genisletme + SaaS Hazirlik + Test Sweep

**Ne:** Dashboard'a impersonation, migration, domain, branding, i18n ekle. SaaS altyapisi hazirla.

**Yapilacaklar:**
- Dashboard genisletme:
  - Admin impersonation UI (impersonate butonu, aktif impersonation banner)
  - Migration import UI (dosya yukle, progress bar, error log)
  - Custom domain yonetimi (ekle, DNS dogrulama durumu, TLS durumu)
  - Branding editor (logo upload, renk secici, preview)
  - Recovery contacts yonetimi (kullanici detay sayfasinda)
  - i18n: Dashboard UI en + tr
- SaaS hazirlik (spec-saas.md icin altyapi):
  - Stripe billing entegrasyon altyapisi (endpoint'ler henuz yok, SDK + webhook handler)
  - Landing page temel yapisi (Next.js static site)

**Test sweep:**
- Integration testler:
  - Impersonation: Start → act as user → restricted ops blocked → end
  - Trusted contacts: Add → verify → initiate recovery → N-of-M approval → access
  - Migration: Auth0 JSON → import → login with old hash → auto-upgrade to Argon2id
  - Custom domain: Add → DNS verify → TLS provision
  - i18n: TR error messages, TR email templates
- SOC 2 evidence:
  - CI/CD logs evidence export calisiyor
  - Audit log compliance export calisiyor
- Coverage: %85+

**Kabul kriterleri:**
- [ ] Dashboard impersonation calisiyor
- [ ] Dashboard migration import calisiyor
- [ ] Dashboard domain yonetimi calisiyor
- [ ] Dashboard branding editor calisiyor
- [ ] Tum integration testler geciyor
- [ ] SOC 2 evidence collection calisiyor
- [ ] Coverage %85+

**Bagimlilk:** T4.1-T4.8

---

## Yeni Audit Event'ler (Faz 4 Eklenen)

| Event | Tetikleme |
|-------|-----------|
| `admin.impersonate.start` | Impersonation baslatildi |
| `admin.impersonate.end` | Impersonation sonlandirildi |
| `recovery.contact.add` | Trusted contact eklendi |
| `recovery.contact.remove` | Trusted contact cikarildi |
| `recovery.initiate` | Recovery baslatildi |
| `recovery.approve` | Contact onayi |
| `recovery.complete` | Recovery tamamlandi |
| `domain.add` | Custom domain eklendi |
| `domain.verify` | Domain dogrulandi |
| `domain.tls.provision` | TLS sertifikasi alindi |
| `migration.start` | Import baslatildi |
| `migration.complete` | Import tamamlandi |

---

## Haftalik Plan (24 hafta — Ay 17-22)

| Hafta | Task'lar | Not |
|-------|----------|-----|
| 1-3 | T4.1 (Admin impersonation — RFC 8693, audit trail, restrictions) | |
| 4-6 | T4.2 (Trusted contacts recovery — N-of-M, email flow, 72h expiry) | |
| 7-9 | T4.3 (Multi-region data residency) + T4.4 (Custom domain + white-label) | Infra |
| 10-12 | T4.5 (Advanced risk + webhooks) + T4.6 (Migration araclari) | |
| 13-14 | T4.7 (i18n en+tr) | |
| 15-20 | T4.8 (Operasyonel prosedurler — SOC 2 + ISO 27001 hazirlik) | Dokumantasyon agirlikli |
| 21-24 | T4.9 (Dashboard + SaaS hazirlik + test sweep) | Final |

**Sertifika:** SOC 2 Type II ALINIR, ISO 27001 baslar, PCI DSS gap analysis
