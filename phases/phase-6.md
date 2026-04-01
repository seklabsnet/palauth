# PalAuth — Faz 6: Next-Gen (AI Agent, EUDI Wallet, KYC)

> Hedef: Next-gen protocol genisletmeleri. AI agent auth + EUDI Wallet + KYC + continuous auth.
> Faz 0-4 (core Go server) + Faz 5 (SDK'lar) tamamlanmis.
> Sertifika basvurulari bu fazda yapilir (FIDO2, FAPI 2.0, ISO 27001, PCI DSS).

---

## Yeni DB Migration'lar

```sql
-- 041_create_agents.up.sql (AI Agent / MCP)
CREATE TABLE agents (
  id              TEXT PRIMARY KEY NOT NULL,
  project_id      TEXT NOT NULL REFERENCES projects(id),
  owner_id        TEXT NOT NULL REFERENCES users(id),
  name            TEXT NOT NULL,
  client_id       TEXT NOT NULL UNIQUE,
  client_secret_hash BYTEA NOT NULL,
  scopes          JSONB NOT NULL DEFAULT '[]',
  max_delegation_level INTEGER NOT NULL DEFAULT 1,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at      TIMESTAMPTZ
);

-- 042_create_agent_delegations.up.sql
CREATE TABLE agent_delegations (
  id              TEXT PRIMARY KEY NOT NULL,
  agent_id        TEXT NOT NULL REFERENCES agents(id),
  user_id         TEXT NOT NULL REFERENCES users(id),
  granted_scopes  JSONB NOT NULL DEFAULT '[]',
  granted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at      TIMESTAMPTZ
);
CREATE INDEX idx_ad_agent ON agent_delegations(agent_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_ad_user ON agent_delegations(user_id) WHERE revoked_at IS NULL;

-- 043_create_verifiable_presentations.up.sql (EUDI Wallet)
CREATE TABLE verifiable_presentations (
  id              TEXT PRIMARY KEY NOT NULL,
  project_id      TEXT NOT NULL REFERENCES projects(id),
  user_id         TEXT REFERENCES users(id),
  presentation    JSONB NOT NULL,         -- VP payload
  issuer          TEXT NOT NULL,
  verified        BOOLEAN NOT NULL DEFAULT false,
  claims_extracted JSONB,                 -- selective disclosure sonucu
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 044_create_kyc_verifications.up.sql
CREATE TABLE kyc_verifications (
  id              TEXT PRIMARY KEY NOT NULL,
  project_id      TEXT NOT NULL REFERENCES projects(id),
  user_id         TEXT NOT NULL REFERENCES users(id),
  provider        TEXT NOT NULL,          -- 'onfido', 'jumio', 'veriff', 'sumsub', 'idnow'
  status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'verified', 'failed', 'expired')),
  level           TEXT NOT NULL CHECK (level IN ('baseline', 'extended')),  -- ETSI TS 119 461
  verification_data_encrypted BYTEA,     -- provider sonucu (AES-GCM)
  completed_at    TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_kyc_user ON kyc_verifications(user_id, created_at DESC);
```

---

## T6.1 — AI Agent / MCP Authentication

**Ne:** Agent entity tipi. OAuth 2.1 client credentials. RFC 8693 token exchange (delegation). MCP server uyumu.

**Yapilacaklar:**
- `internal/agent/service.go`:
  - Agent CRUD (project bazinda)
  - Agent = OAuth 2.1 confidential client (`client_credentials` flow)
  - Scoped permissions: Agent ne yapabilir
- `internal/agent/delegation.go`:
  - RFC 8693 Token Exchange:
    ```
    POST /oauth/token
    grant_type=urn:ietf:params:oauth:grant-type:token-exchange
    subject_token=<user_access_token>
    actor_token=<agent_client_credentials_token>
    scope=read:profile write:tasks
    ```
  - Delegated token claims:
    ```json
    { "sub": "usr_xxx", "act": { "sub": "agent_xxx" }, "scope": "read:profile write:tasks", "may_act": { "sub": "agent_xxx", "max_scope": "read:profile write:tasks" } }
    ```
  - Kullanici delegation onayi: "Bu agent benim adima su islemleri yapabilir"
  - Delegation revoke: Kullanici istediginde delegation iptal edebilir
- `internal/agent/mcp.go`:
  - OAuth 2.1 + PKCE zorunlu (MCP spec)
  - Protected Resource Metadata (RFC 9728): `GET /.well-known/oauth-protected-resource`
  - Client ID Metadata Documents (CIMD) destegi

**Endpoint'ler:**
```
POST   /admin/projects/:id/agents         → { name, scopes } → agent + client_id + client_secret
GET    /admin/projects/:id/agents
DELETE /admin/projects/:id/agents/:aid    → agent revoke
POST   /oauth/token (grant_type=client_credentials, client_id=agent) → agent JWT
POST   /oauth/token (grant_type=token-exchange) → delegated token
GET    /auth/delegations                  → kullanicinin aktif delegasyonlari
POST   /auth/delegations/:id/revoke      → delegation iptal
GET    /.well-known/oauth-protected-resource → Protected Resource Metadata (RFC 9728)
```

**Audit event'ler:** `agent.create`, `agent.revoke`, `agent.delegation.grant`, `agent.delegation.revoke`, `agent.token.issue`, `agent.token.exchange`

**Kabul kriterleri:**
- [ ] Agent olusturma calisiyor (client_id + client_secret)
- [ ] Agent client_credentials flow → JWT donuyor
- [ ] RFC 8693 token exchange → delegated token (act + sub claims)
- [ ] Delegated token scope'u agent scope'u ile sinirli
- [ ] Kullanici delegation revoke edebiliyor
- [ ] Protected Resource Metadata endpoint calisiyor (RFC 9728)
- [ ] MCP PKCE zorunlulugu calisiyor

**Bagimlilk:** Faz 2 (OIDC Provider), Faz 3 (client_credentials, token exchange)

---

## T6.2 — EUDI Wallet / OpenID4VP

**Ne:** EUDI Wallet'lardan Verifiable Credential kabul etme. Selective disclosure. Auth server Verifier rolu.

**Yapilacaklar:**
- `internal/eudi/verifier.go`:
  - OpenID4VP (Verifiable Presentations) ile credential dogrulama:
    1. Authorization Request olustur (hangi credential'lar isteniyor)
    2. Wallet VP (Verifiable Presentation) gonderir
    3. VP signature dogrula (issuer public key ile)
    4. Credential claims extract et
    5. Selective disclosure: Sadece gereken bilgiyi al (orn: "18 yasindan buyuk" → true, dogum tarihi paylasilmaz)
  - SD-JWT VC format destegi
  - Credential issuer dogrulama (trusted issuer listesi)
- `internal/eudi/registration.go`:
  - RP (Relying Party) kayit altyapisi
  - Hangi attributes isteniyor deklarasyonu
  - Data minimization (GDPR) enforcement

**Endpoint'ler:**
```
POST /auth/eudi/verify/begin   → { requested_credentials } → { authorization_request }
POST /auth/eudi/verify/finish  → { vp_token } → { access_token, user, verified_claims }
GET  /admin/projects/:id/eudi  → EUDI config (trusted issuers, requested attributes)
PUT  /admin/projects/:id/eudi  → EUDI config guncelle
```

**Kabul kriterleri:**
- [ ] OpenID4VP authorization request olusturuluyor
- [ ] VP dogrulama calisiyor (imza + issuer)
- [ ] Selective disclosure: Gereksiz attribute paylasilmiyor
- [ ] SD-JWT VC format destekleniyor
- [ ] Dogrulanmis credential ile login/signup calisiyor

**Bagimlilk:** Faz 2 (OIDC Provider — OpenID4VP ayni stack)

---

## T6.3 — KYC Entegrasyon Hook'lari

**Ne:** Identity verification provider entegrasyonu. ETSI TS 119 461 uyumlu.

**Yapilacaklar:**
- `internal/kyc/service.go`:
  - KYC provider interface:
    ```go
    type KYCProvider interface {
      InitiateVerification(ctx context.Context, userID string, level string) (*KYCSession, error)
      CheckStatus(ctx context.Context, sessionID string) (*KYCResult, error)
    }
    ```
  - Provider implementations: Onfido, Sumsub (Faz 5'te en az 1)
  - `before.identity.verify` blocking hook: Backend KYC sonucunu onaylayabilir
  - Verification levels (ETSI TS 119 461):
    - Baseline: Document verification + liveness check
    - Extended: Yuz yuze veya esdeger remote verification
  - Verification status tracking per user

**Endpoint'ler:**
```
POST /auth/kyc/initiate        → { level: "baseline"|"extended" } → { session_url, session_id }
GET  /auth/kyc/status          → { status, level, verified_at }
POST /admin/projects/:id/kyc/config → { provider, api_key_encrypted, level }
```

**Audit event'ler:** `kyc.initiate`, `kyc.complete`, `kyc.failed`

**Kabul kriterleri:**
- [ ] KYC initiate calisiyor (provider'a redirect)
- [ ] KYC status check calisiyor
- [ ] Verification level (baseline/extended) secimi calisiyor
- [ ] `before.identity.verify` hook calisiyor
- [ ] KYC sonucu user profilinde gorunuyor

**Bagimlilk:** Faz 1 (hooks), spec-compliance ETSI TS 119 461

---

## T6.4 — Continuous Auth + Session Transfer

**Session Transfer (spec Section 5.2):**
- Cihazlar arasi session aktarimi (QR code ile)
- Oturumdaki cihaz QR code gosterir, yeni cihaz tarar
- Yeni cihazda session olusur, eski devam eder veya sonlanir (configurable)
- Session transfer sirasinda MFA re-verify gerekli

**Ne:** Session suresince davranissal sinyaller ile risk engine'e surekli girdi.

**Yapilacaklar:**
- `internal/risk/signals/behavioral.go`:
  - Login pattern analizi: Kullanicinin normal login saatleri, gunleri
  - Session icinde request velocity pattern
  - Bu sinyaller risk engine'e ek input olarak gider
  - Anomali tespit edilirse → step-up auth tetikle

**Kabul kriterleri:**
- [ ] Login pattern analizi calisiyor (normal saat disinda → risk artisi)
- [ ] Anomali → step-up auth tetikleniyor
- [ ] Behavioral signals risk engine'de gorunuyor

**Bagimlilk:** Faz 2 (risk engine)

---

---

## T6.5 — Sertifika Basvurulari

**Ne:** SOC 2 (Faz 4'te alindi), ISO 27001, PCI DSS v4.0.1, HIPAA, CSA STAR, FedRAMP hazirlik, eIDAS.

**Yapilacaklar:**
- ISO 27001:
  - Stage 1 (dokumantasyon review) + Stage 2 (implementation audit)
  - ISMS dokumantasyonu (Faz 4'te hazirlandi)
- PCI DSS v4.0.1:
  - QSA audit
  - ASV quarterly scan programi baslat
  - WAF deployment verify
- HIPAA BAA:
  - SOC 2 altyapisi uzerine ek kontroller
- CSA STAR Level 2:
  - ISO 27001 uzerine cloud security ek kontroller
- FedRAMP High hazirlik:
  - 3PAO ile calisma baslat (eger hosted versiyon sunuluyorsa)
  - PIV/CAC auth (Faz 3'te hazirlandi) verify
- eIDAS LoA High:
  - QTSP partnership verify (Faz 3'te entegrasyon yapildi)
- FIDO2 Server L1:
  - Conformance test suite son kez calistir + basvuru yap
- OpenID FAPI 2.0:
  - Conformance test suite son kez calistir + basvuru yap

**Kabul kriterleri:**
- [ ] ISO 27001 Stage 1 gecti
- [ ] ISO 27001 Stage 2 gecti → SERTIFIKA
- [ ] PCI DSS QSA audit basarili → SERTIFIKA
- [ ] HIPAA BAA imzalanabilir durumda
- [ ] CSA STAR Level 2 → SERTIFIKA
- [ ] FIDO2 conformance suite GECIYOR → SERTIFIKA
- [ ] FAPI 2.0 conformance suite GECIYOR → SERTIFIKA
- [ ] FedRAMP 3PAO engagement basladi (eger applicable)

**Bagimlilk:** Tum onceki fazlar + Faz 4 operasyonel prosedurler

---

## T6.6 — Final Test Sweep + Conformance

**Ne:** Tum conformance testleri. Final security audit.

**Yapilacaklar:**
- Conformance test suite'leri:
  - OpenID Connect (Basic OP, Config OP, Dynamic OP) → PASS
  - FIDO2 Server L1 → PASS
  - FAPI 2.0 Security Profile → PASS
  - OpenID4VP conformance → PASS
  - SCIM Okta/Azure AD test suite → PASS
- Full security audit:
  - Tum endpoint'ler OWASP ASVS v5.0 Level 2 kontrol
  - 3rd party pentest sonuclari remediate
  - Mutation testing: Guvenlik modulleri %80+ mutation score
- Coverage: %85+ (guvenlik modulleri %90+)
- SDK'lara Faz 6 ozelliklerini ekle (AI Agent, EUDI endpoint'leri)

**Kabul kriterleri:**
- [ ] Tum conformance testler geciyor
- [ ] OWASP ASVS Level 2 kontrol tamamlandi
- [ ] 3rd party pentest sonuclari remediate edildi
- [ ] Coverage %85+

**Bagimlilk:** T6.1-T6.5

---

## Yeni Audit Event'ler (Faz 5 Eklenen)

| Event | Tetikleme |
|-------|-----------|
| `agent.create` | Agent olusturuldu |
| `agent.revoke` | Agent revoke edildi |
| `agent.delegation.grant` | Delegation verildi |
| `agent.delegation.revoke` | Delegation iptal edildi |
| `agent.token.issue` | Agent JWT verildi |
| `agent.token.exchange` | Delegated token uretildi |
| `eudi.verify.begin` | EUDI dogrulama baslatildi |
| `eudi.verify.complete` | EUDI dogrulama tamamlandi |
| `kyc.initiate` | KYC baslatildi |
| `kyc.complete` | KYC tamamlandi |
| `kyc.failed` | KYC basarisiz |

---

## Haftalik Plan (20 hafta)

| Hafta | Task'lar | Not |
|-------|----------|-----|
| 1-4 | T6.1 (AI Agent / MCP — agent entity, delegation, RFC 8693, MCP compat) | |
| 5-8 | T6.2 (EUDI Wallet — OpenID4VP, SD-JWT VC, selective disclosure) | |
| 9-12 | T6.3 (KYC — provider entegrasyon, ETSI TS 119 461) + T6.4 (Continuous auth) | |
| 13-16 | T6.5 (Sertifika basvurulari — ISO, PCI DSS, HIPAA, CSA, FIDO2, FAPI, eIDAS) | Audit + basvuru |
| 17-20 | T6.6 (Final test sweep + conformance + pentest) | Final |

**Sertifika hedefleri:**
- ISO 27001 ✅ ALINIR
- PCI DSS v4.0.1 ✅ ALINIR
- HIPAA BAA ✅ HAZIR
- CSA STAR Level 2 ✅ ALINIR
- FIDO2 Server L1 ✅ ALINIR
- OpenID FAPI 2.0 ✅ ALINIR
- eIDAS LoA High ✅ HAZIR
- FedRAMP High → SURUYOR (eger applicable)

---

## Tum Fazlar — Migration Ozeti

| Faz | Migration Aralik | Tablo Sayisi |
|-----|------------------|-------------|
| Faz 0 | 001-011 | 11 tablo |
| Faz 1 | 012-020 | 7 tablo + 1 ALTER + trusted_devices |
| Faz 2 | 021-027 | 6 tablo + 1 ALTER |
| Faz 3 | 028-035 | 8 tablo |
| Faz 4 | 036-040 | 5 tablo |
| Faz 6 | 041-044 | 4 tablo |
| **TOPLAM** | **001-044** | **~44 tablo/ALTER** |

> Faz 5 (SDK) ve Faz 7 (SaaS) DB migration gerektirmez.

---

## Tum Fazlar — Spec Coverage Ozeti

| Spec Section | Faz | Task |
|-------------|-----|------|
| 2.1 Email+Password | 0 | T0.7, T0.9, T0.10 |
| 2.2 OTP (TOTP) | 1 | T1.1 |
| 2.2 SMS OTP | 2 | T2.7 |
| 2.3 WebAuthn/Passkeys | 2 | T2.1 |
| 2.4 Social Login | 1 | T1.2 |
| 2.5 Magic Link | 1 | T1.5 |
| 2.6 Phone Auth | 2 | T2.7 |
| 3 MFA | 1 | T1.1 |
| 3.4 Step-Up | 2 | T2.2 |
| 4.1-4.2 JWT + Refresh | 0 | T0.8 |
| 4.3 DPoP | 3 | T3.1 |
| 4.4 Key Rotation | 2 | T2.8 |
| 4.5 Custom Token | 0 | T0.8 |
| 5 Session | 0+1 | T0.13 + T1.5 |
| 6 Device Attestation | 3 | T3.2 |
| 7 Transaction Auth | 3 | T3.3 |
| 8 Hooks | 1 | T1.3 |
| 9 Risk Engine | 2 | T2.3 |
| 10 Bot Detection | 2 | T2.4 |
| 11 Account Recovery | 1+2+4 | T1.1 + T2.1 + T4.2 |
| 12 Organizations | 2 | T2.5 |
| 13 API Key/M2M/PAT | 3 | T3.6 |
| 14 Admin Impersonation | 4 | T4.1 |
| 15 Project Isolation | 0 | T0.6 |
| 16 Audit Log | 0 | T0.11 |
| 17 Encryption | 0 | T0.5 |
| 18 Rate Limiting | 0 | T0.4 |
| 19 Webhooks | 1 | T1.4 |
| 20 OIDC Provider | 2 | T2.6 |
| 21 AI Agent/MCP | 6 | T6.1 |
| 22 EUDI/DID | 6 | T6.2 |
| 23 Breach Detection | 3 | T3.7 |
| 24 Compliance Automation | 3 | T3.7 |
| 35 Email | 0 | T0.12 |
| 36 SAML | 3 | T3.4 |
| 37 HTTP Security | 0 | T0.2 |
| 38 Token Introspection | 0 | T0.8 |
| 41 i18n + Accessibility | 7 | SaaS/Dashboard isi |
| 43 Test Strategy | Her faz | Final sweep per faz |
| 44 Dashboard | 0+1+2+3+4 | Her fazda genisler |
