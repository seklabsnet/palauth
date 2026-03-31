# PalAuth — Sertifikasyon, Regulasyon & Uyum

> Bu dosya PalAuth'un sertifika portfolyosunu, regulasyon uyumunu ve compliance gereksinimlerini icerir.
> Core fonksiyonalite icin: [spec.md](spec.md)
> SDK'lar icin: [spec-sdk.md](spec-sdk.md)
> SaaS platform icin: [spec-saas.md](spec-saas.md)

---

## 1. Hedef Sertifika Portfolyosu

| Sertifika | Tip | Oncelik | Sure | Maliyet | Self-Hosted Uygulanabilir? |
|-----------|-----|---------|------|---------|---------------------------|
| **Temel — Day 1** |
| NIST SP 800-63B-4 (AAL1-3) | Guideline | Day 1 tasarim | - | Ucretsiz | Evet |
| GDPR compliance | Regulation | Day 1 tasarim | Surekli | €20K-€40K setup | Evet |
| PSD2/PSD3 SCA | Regulation | Day 1 tasarim | Surekli | €0 (design) | Evet |
| CSA STAR Level 1 | Self-assessment | Day 1 | 2-4 hafta | **Ucretsiz** | Evet |
| **Faz 1 — Hizli Kazanimlar** |
| OpenID Connect Certified | Self-certification | Ay 1-3 | Gunler-haftalar | €700 (uye) / €3,500 (non-uye) | Evet |
| FAPI 2.0 Certified | Self-certification | Ay 1-3 | 1-3 ay | €1K (uye) / €5K (non-uye) + engineering effort €15K-€40K | Evet |
| FIDO2 Server L1 | Automated test | Ay 1-3 | 2-4 ay | €20K-€50K + uyelik | Evet |
| Penetration test (3rd party) | Rapor | Ay 3 | 2-4 hafta | €5K-€15K | Evet |
| **Faz 2 — Enterprise** |
| SOC 2 Type II | CPA audit | Ay 6-12 | 6-15 ay | €25K-€80K | Evet (reduced scope — dev practices, SDLC) |
| ISO 27001:2022 | Accredited CB | Ay 6-12 | 3-12 ay | €15K-€50K (SOC 2 ile paralel %20-35 tasarruf) | **Tam uygulanabilir** (en degerli sertifika self-hosted icin) |
| HIPAA BAA | BAA | SOC 2 ile | - | €15K-€50K | Evet (reduced — musteri PHI hosting sorumlulugu tasir) |
| DPF (EU-US Data Privacy Framework) | Self-certification | Ay 6 | 2-4 hafta | Minimal | Evet |
| **Faz 3 — Financial + Signing** |
| ISO 27701 (Privacy) | Certification | Ay 13+ | 2-4 ay | €15K-€50K (ISO 27001 uzerine incremental) | Evet |
| DORA readiness | Compliance docs | Ay 13+ | 3-6 ay | €30K-€100K | Evet |
| QTSP partnership | Entegrasyon | Ay 13+ | 1-3 ay | €10K-€50K + €2.50-€5/QES | Evet |
| OpenID4VP/VCI conformance | Self-certification | Ay 13+ | Gunler-haftalar | €700-€3,500 | Evet |
| ETSI TS 119 461 (Identity proofing) | Compliance | Ay 13+ (Agustos 2027 zorunlu) | 2-4 ay | QTSP audit icinde | Evet |
| CSA STAR Level 2 | Certification | ISO 27001 sonrasi | 2-4 ay | €10K-€30K (ISO uzerine) | Evet |
| PCI DSS v4.0.1 | QSA audit | Ay 13-18 | 3-12 ay | €5K-€200K | Evet (reduced — musteri CDE sorumlulugu tasir) |
| **Faz 4 — Global** |
| FIPS 140-3 | Crypto module validation | Ay 24+ | 2-24 ay | €50K-€400K (VaaS ile €50K-€150K, ~2 ay) | **Ideal** (urun-seviye, deployment-agnostic) |
| Common Criteria (EAL2-4) | CCTL evaluation | Ay 24+ | 12-24 ay | €100K-€500K | **Ideal** (urun-seviye) |
| ISO 27017 (Cloud security) | Certification | Ay 24+ | 2-4 ay | €10K-€30K (ISO uzerine) | Evet |
| ISO 27018 (PII in cloud) | Certification | Ay 24+ | 2-4 ay | €10K-€30K (ISO uzerine) | Evet |
| FedRAMP High | US gov authorization | Sadece hosted versiyon icin | 12-24 ay | €500K-€2M+ (PIV/CAC zorunlu IA-2(12)) | **HAYIR** — cloud-only. Self-hosted icin FISMA ATO kullanilir |
| QTSP status (own) | EU Trusted List | Volume hakliyorsa | 2-3 yil | €500K-€1M+ initial, €200K-€500K/yil | Kismi |
| eIDAS LoA High | EU regulation | Ay 24+ | 2-6 ay | €10K-€100K | Evet |

### Self-Hosted Avantaji

FIPS 140-3, Common Criteria, FIDO2, FAPI gibi **urun-seviye sertifikalar** deployment modeline bagli degil — yazilimla birlikte gider. SOC 2, HIPAA, PCI DSS gibi operasyonel sertifikalarda ise scope daraliyor cunku musteri kendi altyapisini yonetiyor.

**Strateji:** Urun sertifikalarina (FIDO2, FAPI, FIPS, CC) agirlik ver. Operasyonel sertifikalari (SOC 2, ISO 27001) satista "must have" oldugu icin al. Compliance'i urune gom: audit log export, compliance dashboard, hardening guide, STIG config, responsibility matrix.

**FedRAMP notu:** Self-hosted yazilim FedRAMP'a tabi degil. Musterinin altyapisinda calisan yazilim FISMA agency-level ATO ile degerlendirilir. Eger ileride hosted component sunarsak sadece o component FedRAMP gerektirir.

### Maliyet Ozeti

| Faz | Sure | Min Maliyet | Max Maliyet | Kumulatif Min | Kumulatif Max |
|-----|------|-------------|-------------|---------------|---------------|
| Faz 1: MVP Auth | Ay 1-6 | €40K | €100K | €40K | €100K |
| Faz 2: Enterprise | Ay 7-12 | €75K | €230K | €115K | €330K |
| Faz 3: Financial + Signing | Ay 13-24 | €75K | €340K | €190K | €670K |
| Faz 4: Global | Ay 24-36 | €270K | €1M | €460K | €1.67M |
| Yillik bakim (3. yil sonrasi) | Surekli | €40K/yil | €120K/yil | — | — |

**Opsiyonel yuksek maliyetler (dahil degil):**

| Opsiyonel | Maliyet | Ne zaman |
|-----------|---------|----------|
| FedRAMP Moderate/High | €500K-€2M+ | Sadece US gov geliri hakliyorsa |
| QTSP (kendi) | €500K-€1M+ initial + €200K-€500K/yil | 10,000-50,000+ QES/ay hacminde |
| Common Criteria EAL4+ | €200K-€500K+ | Sadece QSCD donanimi yapiyorsak |

**Gercekci startup yolu (Faz 1-3): €190K-€670K / 2 yil.**

---

## 2. NIST 800-63B-4 Authentication Assurance Levels

### AAL1 (Some Confidence)
- Single-factor authentication
- Password (min 15 chars single-factor, min 8 chars with MFA, blocklist check) OR single-factor OTP
- Absolute timeout: SHALL be established, SHOULD 30 days
- Idle timeout: No requirement
- No MitM resistance required

### AAL2 (High Confidence)
- Two different authentication factors
- Password + TOTP, or password + WebAuthn, or multi-factor crypto device
- SMS OTP allowed but restricted (user must be warned, alternative offered)
- **SHALL offer at least one phishing-resistant option** (NIST 800-63B-4 Sec 2.2.2)
- Idle timeout: SHOULD 1 hour
- Absolute timeout: SHOULD 24 hours
- MitM resistance required
- Authentication intent required (physical action)

### AAL3 (Very High Confidence)
- Two factors, at least one hardware cryptographic device
- WebAuthn hardware key + PIN/biometric, or hardware OTP + crypto device
- Idle timeout: SHOULD 15 minutes
- Absolute timeout: SHALL 12 hours
- MitM resistance required
- Verifier impersonation resistance required (rpId binding — WebAuthn provides this)
- Authentication intent required
- Software-only authenticators DO NOT qualify

---

## 3. NIST vs PCI DSS Catisma Cozumleri

### Password Policy

| Konu | NIST 800-63B-4 | PCI DSS v4.0.1 | Cozum |
|------|----------------|-----------------|-------|
| Min uzunluk (single-factor) | **15 karakter (SHALL)** | 12 karakter (Req 8.3.6) | **15 karakter** (daha siki olan kazanir) |
| Composition rules | **SHALL NOT** impose | Numerik + alfa zorunlu (Req 8.3.6) | Composition uygulanmaz — compensating control: 15+ char + HIBP + full NIST control set. QSA validation gerekir |
| Periyodik rotation | **SHALL NOT** require | 90 gun (Req 8.3.9) | MFA aktifse Req 8.3.9 gecerli degil (scope condition). MFA olmadan 90 gun rotation |
| Compromised check | **SHALL** check | Belirtilmemis | HaveIBeenPwned k-Anonymity API zorunlu |

### Session Timeout (NIST 800-63B-4 Rev 4 — Agustos 2025)

| AAL | Idle Timeout | Absolute Timeout | Not |
|-----|-------------|-----------------|-----|
| AAL1 | Gereksinim yok | SHALL var, SHOULD 30 gun | |
| AAL2 | SHOULD 1 saat | SHOULD 24 saat | Rev 3'ten farkli: 30dk->1sa, 12sa->24sa, SHALL->SHOULD |
| AAL3 | SHOULD 15dk | SHALL 12 saat | Deger ayni, keyword SHALL->SHOULD (idle icin) |

> **SHALL vs SHOULD**: SHALL = zorunlu, SHOULD = strongly recommended. Rev 4'te AAL2 timeout'lari SHOULD'a gecti — esneklik sagliyor ama uygulamayi oneririz.

---

## 4. OpenID Connect / OAuth 2.1 Compliance

### Endpoints (Go server implementasyonu)

| Endpoint | Purpose |
|----------|---------|
| `GET /.well-known/openid-configuration` | Discovery |
| `GET /.well-known/jwks.json` | Public keys |
| `POST /oauth/authorize` | Authorization (with PAR support) |
| `POST /oauth/token` | Token exchange |
| `GET /oauth/userinfo` | User claims |
| `POST /oauth/revoke` | Token revocation (RFC 7009) |
| `POST /oauth/introspect` | Token introspection (RFC 7662) |
| `POST /oauth/par` | Pushed Authorization Request (FAPI) |
| `POST /oauth/device` | Device Authorization Grant (RFC 8628) |

### Hedeflenen OpenID Sertifikasyon Profilleri

- Basic OP, Config OP, Dynamic OP, Form Post OP
- FAPI 2.0 Security Profile
- Logout profilleri (RP-Initiated, Session, Front-Channel, Back-Channel)

### FAPI 2.0 Security Profile (Final, Subat 2025)

- **Algoritmalar:** Sadece PS256, ES256, EdDSA (Ed25519). **RS256 YASAK**
- Authorization code max omur: **60 saniye** (Sec 5.3.2.1 — SHALL)
- PAR request_uri expiry: **600 saniye altinda** (Sec 5.3.2.2 — SHALL)
- Sadece **confidential client'lar** (public client YASAK)
- HTTP 307 redirect YASAK (sadece 303)
- RFC 9207 issuer identification zorunlu (`iss` parameter)
- Sender-constrained access token zorunlu: mTLS (RFC 8705) veya DPoP (RFC 9449). Bearer-only YASAK
- PKCE S256 zorunlu
- **Refresh token rotation: SHALL NOT** — FAPI modunda rotation degil, sender-constraining ile guvenlik saglenir
- JARM: Base Security Profile'da GEREKLI DEGIL (sadece Message Signing profile'da)
- `s_hash` kaldirildi — PKCE ile degistirildi
- Token lifetime: Normatif zorunluluk YOK. Sec 6.1 non-normative: "consider using short-lived access tokens"

### OAuth 2.1 (draft-ietf-oauth-v2-1-15, Mart 2026 — henuz RFC degil)

- PKCE zorunlu (S256 only, plain method kaldirildi)
- Implicit grant kaldirildi
- Resource Owner Password Credentials grant kaldirildi
- Refresh token: sender-constrained veya one-time use
- Bearer token URI query parameter'da YASAK
- Exact redirect URI string matching zorunlu

---

## 5. FIDO2 Server Certification Requirements

### Conformance Tests

- WebAuthn API compliance (create + get ceremony)
- CBOR encoding/decoding
- Signature verification (ES256 zorunlu, RS256 ve EdDSA onerilen)
- Challenge handling (16+ byte random, single-use)
- Origin validation (rpId matching)
- User presence (UP) ve user verification (UV) flag checking
- Counter validation ve clone detection
- **BE/BS backup flags** (WebAuthn Level 3): BE=0/BS=0 device-bound (AAL3), BE=1/BS=1 synced (AAL2)

### Attestation Formats

| Format | Gereksinim |
|--------|------------|
| packed | **Zorunlu** — self-attestation + full attestation with x5c chain |
| none | **Zorunlu** — privacy-preserving scenarios |
| android-key | **Zorunlu** — SafetyNet Mayis 2025'te kapandi, tek aktif Android format |
| fido-u2f | Onerilen — backward compat |
| tpm | Onerilen — Windows Hello |
| apple | Onerilen — Apple platform authenticators |

`android-safetynet` deprecated (Mayis 2025 oncesi legacy icin read-only). `compound` format tracking (WebAuthn Level 3 Sec 8.9).

### Metadata Service

- FIDO MDS v3 entegrasyonu
- Compromised authenticator model tespiti
- AAGUID-based policy enforcement

---

## 6. PSD2/PSD3 SCA Compliance

### Strong Customer Authentication

- Two of three factors: knowledge + possession + inherence
- Factors must be independent
- Dynamic linking for payment transactions (amount + payee bound to auth code)
- WYSIWYS (What You See Is What You Sign)
- Max 5-minute auth code lifetime
- Max 5 failed attempts
- Max 5-minute session inactivity timeout

### PSD3/PSR (Politik anlasma: 27 Kasim 2025, PSR yururluk: H2 2027 - basi 2028)

**SCA kurallari artik PSR Articles 85-89'da** (dogrudan uygulanabilir regulation):
- Iki inherence faktoru izinli (orn: parmak izi + yuz tanima) — SADECE inherence kategorisinde
- Genisletilmis SCA kapsami: login, mandate setup, cihaz recovery
- SCA erisilebirligi yasal hak: akilli telefon disinda yontemler zorunlu
- SCA delegasyonu = outsourcing
- Impersonation fraud sorumlulugu PSP'lerde
- Gercek zamanli fraud monitoring zorunlu

### SCA Exemptions Engine

- Low-value transactions (< EUR 30, cumulative limits)
- Recurring transactions (same amount + payee after initial SCA)
- Trusted beneficiaries (user-whitelisted)
- Transaction Risk Analysis (TRA) based on fraud rates
- Merchant-initiated transactions

---

## 7. GDPR Compliance

| Requirement | Article | Implementation |
|-------------|---------|----------------|
| Data minimization | Art. 5 | Collect only email + password hash. No unnecessary PII |
| Right to erasure | Art. 17 | User deletion + cryptographic erasure in logs |
| Data portability | Art. 20 | JSON export endpoint |
| Consent management | Art. 6/7 | Granular consent recording per purpose |
| Breach notification | Art. 33 | 72-hour notification to supervisory authority |
| DPIA | Art. 35 | Completed before deployment |
| Privacy by design | Art. 25 | Default settings = most privacy-protective |
| Pseudonymization | Art. 25 | Pseudonymized identifiers in logs |
| International transfers | Chapter V | Standard Contractual Clauses or adequacy decisions |

---

## 8. DORA (Digital Operational Resilience Act)

**17 Ocak 2025'te yururluge girdi.** Auth platformu banka musterilerine hizmet verdiginde ICT ucuncu taraf hizmet saglayicisi olarak DORA'ya tabi.

### Sozlesme Gereksinimleri (Art. 28-30)
- SLA'lar (uptime, response time, RTO/RPO)
- Cikis stratejisi (exit plan)
- Denetim haklari (musteri/regulator)
- Olay bildirimi (24 saat)
- Is surekliligi testi

### Teknik Gereksinimler
1. ICT risk management framework
2. Incident classification ve reporting
3. Digital operational resilience testing (TLPT)
4. Ucuncu taraf risk yonetimi
5. Bilgi ve istihbarat paylasimi (Chapter VI, Art. 45)

### Cezalar
- Finansal kurumlar: yillik dunya cirosunun %2'sine kadar (Art. 50-52)
- Kritik ICT Ucuncu Taraf (CTPP): gunluk cirosunun %1'i + €5M'a kadar

### Implementasyon (€30K-€100K)
- DORA-compliant sozlesme template'leri
- SLA/SLO dokumantasyonu
- Incident response + reporting (24 saat)
- Exit/transition plani
- Denetim erisim mekanizmasi
- Is surekliligi test raporu (6 aylik)

---

## 9. FIPS 140-3

### Nedir?
Kriptografik modullerin guvenligini dogrulayan ABD federal standardi. FIPS 140-2 **21 Eylul 2026'da** sunset.

### Self-Hosted icin Ideal
Urun-seviye sertifika — deployment modeline bagli degil. Go 1.24 native FIPS 140-3 module (sertifika A6650, cgo gerektirmez).

### Uygulama
- **Yol 1:** Go 1.24 native FIPS module (oneri)
- **Yol 2:** VaaS (SafeLogic) — €50K-€150K, ~2 ay

### FIPS Mode
- Project bazinda toggle (`PALAUTH_FIPS=true`)
- Approved algoritmalar: AES-128/192/256, SHA-2, HMAC, RSA 2048+, ECDSA P-256/P-384, EdDSA
- YASAK: Chacha20, MD5, SHA-1 (signing), RSA 1024
- Argon2id FIPS-approved degil — FIPS modunda PBKDF2-HMAC-SHA256 (600K+ iteration) kullanilir

---

## 10. ETSI TS 119 461 (Identity Proofing)

**Agustos 2027'de zorunlu** (EU Implementing Regulation 2025/1566).

### Seviyeler
- **Baseline Level**: Document verification + liveness check
- **Extended Level**: Yuz yuze veya esdeger remote verification

### PalAuth Rolu
- QTSP partnership yaptigimizda QTSP zaten uyumlu olmali
- Auth server: KYC provider entegrasyonu (Onfido, Veridas, Sumsub, IDnow)
- `before.identity.verify` blocking hook ile backend KYC sonucunu onaylar

---

## 11. QES (Qualified Electronic Signature) Stratejisi

### QTSP Partnerligi vs Kendi QTSP

| | Partnerllik | Kendi QTSP |
|---|---|---|
| Sure | 1-3 ay | 2-3 yil |
| Maliyet | €10K-€50K + €2.50-€5/QES | €500K-€1M+ |
| Breakeven | - | 10,000-50,000+ QES/ay |

**Karar: Faz 3'te partnership.** Kendi QTSP ancak volume hakliyorsa Faz 5'te.

### Potansiyel Partnerler
- Swisscom Trust Services, Namirial, InfoCert, SK ID Solutions, Evrotrust

### Entegrasyon
- CSC API (ETSI TS 119 432)
- Document hash signing (dokuman QTSP'ye gonderilmez)

---

## 12. Data Residency & Sovereignty

- Region-based deployment: EU, US, APAC, TR
- Encryption key'ler region-local KMS'te
- Cross-region veri transferi YASAK (GDPR Art. 44-49)
- DPA (Data Processing Agreement) her musteri ile (GDPR Art. 28)

---

## 13. Altyapi Guvenligi & Operasyonel Prosedurler

### Backup & DR
- RPO: Max 1 saat, RTO: Max 4 saat
- PostgreSQL PITR, Redis AOF + snapshot
- Encrypted backup'lar, ayri region'da kopya
- DR testi: 6 ayda bir (SOC 2 kaniti)

### Network Segmentation
- Auth server kendi VPC'sinde (PCI DSS zorunlu)
- DB public'ten erisilemez
- Bastion/VPN admin erisimi

### Change Management
- PR + review + approval (min 1 reviewer)
- Staging test zorunlu
- Rollback proseduru + emergency change sureci

### Incident Response
1. Detection → 2. Triage (P1-P4) → 3. Containment → 4. Eradication → 5. Recovery → 6. Post-mortem
- GDPR breach notification: 72 saat
- Yillik tabletop exercise (SOC 2 kaniti)

### Vulnerability Management
- Dependency scan: Her CI/CD
- Container scan: Her build
- DAST: Aylik
- Pentest: Yillik (3rd party, PCI DSS zorunlu)
- SLA: Critical=7 gun, High=30 gun, Medium=90 gun

---

## 14. Rakip Sertifika Karsilastirmasi

| Ozellik | PalAuth | Auth0 | Firebase | Supabase | Descope | Hanko | WorkOS | Zitadel | Ory | SuperTokens |
|---------|---------|-------|----------|----------|---------|-------|--------|---------|-----|-------------|
| OpenID FAPI 2.0 | Hedef | FAPI 1 | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir |
| FIDO2 Certified | Hedef | Hayir | Hayir | Hayir | Evet | Evet | Hayir | Hayir | Hayir | Hayir |
| OpenID Certified | Hedef | Evet | Evet* | Hayir | Hayir | Hayir | Hayir | Evet | Evet (Hydra) | Hayir |
| SOC 2 Type II | Hedef | Evet | Evet | Evet | Evet | Hayir | Evet | Evet | Evet | Evet |
| ISO 27001 | Hedef | Evet | Evet | Beklemede | Evet | Hayir | Hayir | Evet | Evet | Hayir |
| PCI DSS v4.0.1 | Hedef | Evet | Evet | Hayir | Evet | Hayir | Hayir | Hayir | Hayir | Hayir |
| FedRAMP High | Hedef | Hayir | Evet* | Hayir | Evet | Hayir | Hayir | Hayir | Hayir | Hayir |
| HIPAA | Hedef | Evet | Evet | Evet | Evet | Hayir | Evet | Hayir | Hayir | Hayir |
| PSD2/PSD3 SCA | Hedef | Evet | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir |
| eIDAS / EUDI | Hedef | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir |
| Self-hosted | Evet | Hayir | Hayir | Evet | Hayir | Evet | Hayir | Evet | Evet | Evet |
| PIV/CAC Auth | Hedef | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir |

*\* = inherited from Google Cloud*

**Hicbir provider tam portfolyoye sahip degil. Descope en yakini (SOC 2 + ISO + FIDO + FedRAMP High).**
