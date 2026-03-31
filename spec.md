# Auth Server - Technical Specification

> Self-hosted, certification-ready authentication & authorization platform.
> NestJS backend, Client SDK + Server SDK, financial-grade security.

---

## 1. Vizyon & Hedefler

### 1.1 Ne Yapacagiz?

Firebase Auth, Supabase Auth, Auth0 gibi calisacak ama self-hosted, tum sertifikalara sahip, finansal islemleri destekleyen bir authentication platformu.

### 1.2 Temel Ilkeler

1. **Security-first**: Tum sertifikalari alabilecek seviyede guvenlik (SOC 2, ISO 27001, PCI DSS, FIDO2, OpenID FAPI, FedRAMP, eIDAS)
2. **Blocking pipeline**: Event-based degil, backend "tamam" demeden islem tamamlanmaz
3. **Entegrasyon kolayligi**: 3 satirda entegrasyon, developer-friendly SDK
4. **Multi-tenant**: Farkli platformlara hizmet verebilecek izolasyon
5. **Financial-grade**: Para transferi, transaction approval, document signing destegi

### 1.3 Hedef Sertifika Portfolyosu

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
| FIDO2 Server L1 | Automated test | Ay 1-3 | 2-4 ay | **€20K-€50K** + uyelik | Evet |
| Penetration test (3rd party) | Rapor | Ay 3 | 2-4 hafta | €5K-€15K | Evet |
| **Faz 2 — Enterprise** |
| SOC 2 Type II | CPA audit | Ay 6-12 | 6-15 ay | €25K-€80K | Evet (reduced scope — dev practices, SDLC) |
| ISO 27001:2022 | Accredited CB | Ay 6-12 | 3-12 ay | €15K-€50K (SOC 2 ile paralel %20-35 tasarruf) | **Tam uygulanabilir** (en degerli sertifika self-hosted icin) |
| HIPAA BAA | BAA | SOC 2 ile | - | €15K-€50K | Evet (reduced — musteri PHI hosting sorumlulugu tasir) |
| DPF (EU-US Data Privacy Framework) | Self-certification | Ay 6 | 2-4 hafta | Minimal | Evet |
| **Faz 3 — Financial + Signing** |
| ISO 27701 (Privacy) | Certification | Ay 13+ | 2-4 ay | €15K-€50K (ISO 27001 uzerine incremental) | Evet |
| DORA readiness | Compliance docs | Ay 13+ | 3-6 ay | **€30K-€100K** | Evet |
| QTSP partnership | Entegrasyon | Ay 13+ | 1-3 ay | €10K-€50K + €0.50-€5/QES | Evet |
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

> **Self-hosted avantaji:** FIPS 140-3, Common Criteria, FIDO2, FAPI gibi **urun-seviye sertifikalar** deployment modeline bagli degil — yazilimla birlikte gider. SOC 2, HIPAA, PCI DSS gibi operasyonel sertifikalarda ise scope daraliyor cunku musteri kendi altyapisini yonetiyor.

> **Strateji:** Urun sertifikalarina (FIDO2, FAPI, FIPS, CC) agirlik ver — bunlar self-hosted'da en yuksek degeri tasiyor. Operasyonel sertifikalari (SOC 2, ISO 27001) satista "must have" oldugu icin al. Compliance'i urune gom: audit log export, compliance dashboard, hardening guide, STIG config, responsibility matrix.

> **FedRAMP notu:** Self-hosted yazilim FedRAMP'a tabi degil. Musterinin altyapisinda calisan yazilim FISMA agency-level ATO ile degerlendirilir. Eger ileride hosted component (management console, telemetry) sunarsak sadece o component FedRAMP gerektirir.

### 1.4 Sertifika Maliyet Ozeti

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
| QTSP (kendi) | €500K-€1M+ initial + €200K-€500K/yil | 1,000+ QES/ay hacminde |
| Common Criteria EAL4+ | €200K-€500K+ | Sadece QSCD donanimi yapiyorsak |

**Gercekci startup yolu (Faz 1-3, opsiyoneller haric): €190K-€670K / 2 yil.** Descope/Stytch ile rekabet paritesi, Clerk/WorkOS'u sertifika genisliginde gecer, signing + financial-grade onlarda yok.

---

## 2. Authentication Yontemleri

### 2.1 Email + Password

- **Minimum 15 karakter** (tek faktorlu auth icin — NIST 800-63B-4 Sec 3.1.1.2, SHALL). MFA aktif ise minimum 8 karakter yeterli
- Max 64 karakter ust limit, truncate yasak (NIST 800-63B-4)
- Composition rules (numerik + alfa zorunlulugu) UYGULANMAZ (NIST 800-63B-4 SHALL NOT). PCI DSS v4.0.1 Req 8.3.6 bunu zorunlu kiliyor — bu catisma compensating control ile dokumante edilir: 15+ karakter uzunlugu composition kuralini gereksiz kilar
- Son 4 sifre tekrar yasak (PCI DSS v4.0.1 Req 8.3.7)
- Compromised password kontrolu: HaveIBeenPwned k-Anonymity API (NIST 800-63B-4 zorunlu)
- Hashing: **Argon2id** (m=64MB+, t=3, p=1, ~300ms target)
- Pepper: HMAC-SHA256, HSM/KMS'te saklanir, DB'de tutulmaz
- Salt: 16+ byte, her password'a unique, `crypto.randomBytes()`
- Max 10 basarisiz deneme -> 30dk lockout (PCI DSS v4.0.1 Req 8.3.4)
- Constant-time karsilastirma: `crypto.timingSafeEqual` (timing attack korunmasi)

### 2.2 OTP (One-Time Password)

**TOTP (Time-based)**
- RFC 6238 uyumlu
- 6 haneli, 30sn window
- Clock drift toleransi: max 1-2 onceki/sonraki kod (30-60sn)
- TOTP secret'lari AES-256-GCM ile sifreli saklanir (hash degil, dogrulama icin geri alinabilir olmali)
- Authenticator app entegrasyonu: Google Authenticator, Authy, 1Password, vb.

**Email OTP**
- 6 haneli, 5dk gecerlilik (PSD2 RTS max 5dk)
- Rate limit: 3 basarisiz deneme -> yeni OTP gerekli
- Replay korumasi: her OTP tek kullanimlik, kullanilan OTP hash'i saklanir

**SMS OTP (Restricted)**
- NIST 800-63B "restricted" siniflandirmasi
- Sadece fallback olarak sunulur
- Kullanici SIM-swap riski hakkinda uyarilir
- Yuksek guvenlik modunda devre disi birakilabilir

### 2.3 WebAuthn / Passkeys (FIDO2)

- FIDO2 Server sertifikasi hedeflenir
- Desteklenen attestation formatlari: **packed** (zorunlu), **none** (zorunlu), **android-key** (zorunlu — SafetyNet Mayis 2025'te kapandi, android icin tek aktif format), fido-u2f, tpm, apple
- `android-safetynet` deprecated (Mayis 2025 oncesi legacy credential'lar icin read-only destek)
- `compound` format tracking (WebAuthn Level 3 Sec 8.9 — henuz IANA'da degil)
- Minimum algoritma: ES256 (zorunlu), EdDSA, RS256 (non-FAPI), PS256 (FAPI zorunlu)
- **Backup Eligibility (BE) ve Backup State (BS) flag'leri** (WebAuthn Level 3):
  - BE=0, BS=0: Device-bound credential — AAL3 uygun, en yuksek guven
  - BE=1, BS=0: Sync-eligible ama henuz yedeklenmemis — kullaniciya recovery uyarisi goster
  - BE=1, BS=1: Synced passkey (iCloud/Google) — AAL2 uygun, recovery mevcut
  - BE=0, BS=1: Gecersiz kombinasyon — reddet
  - BE registration'da set edilir (degismez), BS her ceremony'de guncellenir
  - AAL-based policy enforcement: BE=0 ise AAL3 izin ver, BE=1 ise max AAL2
- Challenge: 16+ byte `crypto.randomBytes()`, tek kullanimlik
- Counter validation: clone detection icin signCount kontrolu
- FIDO MDS v3 entegrasyonu: compromised authenticator tespiti
- rpId ve origin dogrulamasi
- User Presence (UP) ve User Verification (UV) flag kontrolu
- CBOR decoding/encoding
- Passkey-first kayit akisi: sifre olusturmadan sadece passkey ile kayit
- Cross-device QR code login: WebAuthn hybrid transport

**NIST 800-63B AAL Seviyeleri:**
- AAL1: Tek faktor (password veya single-factor OTP)
- AAL2: Iki faktor, MitM direnci zorunlu. Passkey (synced) AAL2 karsilar
- AAL3: Iki faktor + hardware cryptographic authenticator zorunlu. Device-bound passkey + PIN/biometric

### 2.4 Social Login (OAuth 2.0 / OpenID Connect)

**Desteklenen flow: Authorization Code + PKCE (tek flow)**
- Implicit flow desteklenmez (OAuth 2.1 draft-ietf-oauth-v2-1-15 tarafindan kaldirildi — henuz RFC degil ama core gereksinimleri stabil)
- PKCE tum client'lar icin zorunlu, sadece S256 (plain method kaldirildi)
- Resource Owner Password Credentials grant desteklenmez (OAuth 2.1'de kaldirildi)
- Bearer token URI query parameter'da YASAK (sadece Authorization header ve form body)

**Provider'lar:**
- Google, Apple, Microsoft, GitHub, Facebook/Meta, X/Twitter, LinkedIn, Discord, Slack, Spotify
- Generic OIDC: Issuer URL ile auto-discovery
- Generic OAuth 2.0: Manuel endpoint konfigurasyonu

**Akislar:**

*Web SPA:*
```
Client SDK -> redirect/popup -> Provider consent -> callback -> Auth Server token exchange -> Session tokens
```

*Mobile Native:*
```
Native SDK (Google/Apple Sign-In) -> Provider token -> auth.signInWithCredential(token) -> Auth Server dogrulama -> Session tokens
```

*Backend-to-Backend:*
```
Server SDK -> provider token alir -> Auth Server API ile dogrular -> Session tokens
```

**Account Linking:**
- Ayni verified email ile otomatik baglama
- Farkli email'ler icin authenticated session uzerinden manuel baglama
- Admin tarafindan baglama
- Unverified email ile otomatik baglama YASAK

### 2.5 Magic Link (Passwordless Email)

- Tek kullanimlik, 15dk gecerlilik
- Token: 256-bit `crypto.randomBytes()`, SHA-256 hash'i DB'de saklanir
- Kullanildiktan sonra aninda invalidate
- Rate limit: Kullanici basina 5dk'da 1 magic link

### 2.6 Phone Auth

- SMS ile dogrulama kodu
- WhatsApp Business API entegrasyonu (opsiyonel)
- Rate limit: Numara basina 1dk'da 1 kod
- Ulke bazli beyaz/kara liste

---

## 3. Multi-Factor Authentication (MFA)

### 3.1 Zorunluluk Matrisi

| Senaryo | MFA Zorunlu mu? | Standart |
|---------|-----------------|----------|
| Admin paneli erisimi | Evet | SOC 2, PCI DSS 8.4.1 |
| CDE (Cardholder Data) erisimi | Evet | PCI DSS 8.4.2 |
| Uzaktan erisim | Evet | PCI DSS 8.4.3 |
| Finansal islem onayi | Evet | PSD2 SCA |
| Normal kullanici girisi | Tenant tarafindan yapilandirilabilir | - |

### 3.2 MFA Faktorleri

- **Knowledge**: Password, PIN
- **Possession**: TOTP, SMS OTP, Email OTP, Hardware key (FIDO2), Trusted device
- **Inherence**: Biometric (cihaz uzerinden, server'a biyometrik veri gonderilmez)

### 3.3 MFA Kurallari

- Iki farkli faktor kullanilmali, ayni faktorun iki ornegi kabul edilmez (PCI DSS)
- Replay saldirilarina dayanikli olmali (PCI DSS)
- MFA bypass yasak, istisna = yonetim onayi + sure limiti + dokumantasyon (PCI DSS 8.5.1)
- Max 5 basarisiz MFA denemesi -> lockout (PSD2 RTS)
- MFA tamamlandiktan sonra session ID yenilenir (OWASP)
- **AAL2'de en az bir phishing-resistant secenek SUNULMALI** (NIST 800-63B-4 Sec 2.2.2 — SHALL). Yani passkey/WebAuthn her AAL2 deployment'da mevcut olmali, kullanici secmese bile
- Sifre periyodik rotasyonu UYGULANMAZ (NIST 800-63B-4 SHALL NOT). PCI DSS v4.0.1 Req 8.3.9 sadece single-factor auth icin gecerli — MFA aktif ise rotation gereksiz
- Inaktif hesaplar 90 gun sonra devre disi birakilir veya silinir (PCI DSS v4.0.1 Req 8.2.6)

### 3.4 Step-Up Authentication (RFC 9470)

- Hassas islemler icin mevcut session uzerinde ek dogrulama
- **RFC 9470** (Standards Track, Eylul 2023) protokolune uyumlu:
  - Resource server yetersiz auth seviyesi tespit ettiginde: `HTTP 401 WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="urn:nist:800-63:aal2", max_age=300`
  - Client yeni authorization request'e `acr_values` ve `max_age` parametrelerini ekler
  - AS karsilayamiyorsa `unmet_authentication_requirements` hatasi doner
- Access token'larda `acr` ve `auth_time` claim'leri zorunlu (RFC 9068 JWT access token / RFC 9470 Sec 6.2)
- AS `acr_values_supported` metadata field'ini yayinlar
- ACR (Authentication Context Class Reference) ve AMR (Authentication Methods References) claim'leri ile yonetilir
- Ornek: Kullanici giris yapti (AAL1) -> para transferi istedi -> passkey ile step-up (AAL2/AAL3) -> yeni token issued with higher ACR
- Step-up token'lari kisa omurlu (5-15dk)

---

## 4. Token Mimarisi

### 4.1 Access Token (JWT)

- Format: JWT (RFC 7519)
- Imzalama (genel mod): RS256, PS256, ES256, veya EdDSA
- Imzalama (FAPI 2.0 modu): **Sadece PS256, ES256, veya EdDSA (Ed25519 only)** (RS256 YASAK — RSASSA-PKCS1-v1_5 FAPI 2.0 Sec 5.4.1 tarafindan yasaklandi)
- Omur (genel mod): 15-60dk (tenant yapilandirilabilir)
- Omur (FAPI 2.0 modu): Kisa omur ONERILIR ama normatif zorunluluk YOK. FAPI 2.0 Sec 6.1 non-normative: "consider using short-lived access tokens." **Varsayilan: 5dk.** Tenant override edebilir
- Claims: `sub`, `iss`, `aud`, `exp`, `iat`, `jti`, `kid`, `acr`, `amr`, `auth_time`, `tenant_id`, custom claims
- `auth_time` claim'i zorunlu (RFC 9068 + RFC 9470 step-up auth icin gerekli)
- JWKS endpoint: `/.well-known/jwks.json` — public key'ler burada yayinlanir

**FAPI 2.0 ek zorunluluklar (Sec 5.3):**
- Authorization code max omur: **60 saniye** (Sec 5.3.2.1 item 11 — SHALL)
- PAR request_uri expiry: **600 saniye altinda** (Sec 5.3.2.2 item 12 — SHALL)
- Sadece **confidential client'lar** desteklenir (Sec 5.3.2.1 item 3 — SHALL). Public client YASAK
- HTTP 307 redirect YASAK (Sec 5.3.2.2 item 10 — SHALL NOT). Sadece 303 kullan
- RFC 9207 issuer identification zorunlu — `iss` parameter donmeli (Sec 5.3.2.2 item 7 — SHALL)
- Sender-constrained access token'lar zorunlu: mTLS (RFC 8705) veya DPoP (RFC 9449). Bearer-only token YASAK
- PKCE S256 zorunlu (Sec 5.3.2.2 item 5)
- **Refresh token rotation: SHALL NOT** (Sec 5.3.3) — "SHALL NOT use refresh token rotation except in extraordinary circumstances." FAPI modunda rotation degil, sender-constraining (DPoP/mTLS) ile guvenlik saglenir. Istisnai durumlarda rotation kullanilirsa mandatory retry window gerekli
- JARM: Base Security Profile'da GEREKLI DEGIL (sadece Message Signing profile'da)
- `s_hash` claim'i kaldirildi — PKCE ile degistirildi

### 4.2 Refresh Token (Opaque)

- Format: Opaque string — 256-bit `crypto.randomBytes()`
- Saklama: Server-side (DB), SHA-256 hash olarak
- Rotation: Her kullanildiginda yeni refresh token uretilir, eski invalidate edilir
- Family-based revocation: Eski bir refresh token tekrar kullanilirsa, tum token ailesi (descendants) iptal edilir (stolen token tespiti)
- Reuse grace period: **30 saniye** (Okta default, production-tested at scale). 2-5sn cok agresif — mobil uygulamalarda network latency, background/foreground gecisleri ve retry storm'lari false-positive revocation'a neden olur. RFC 9700 sure belirtmiyor, 10-30sn arasi ideal

### 4.3 DPoP (Demonstration of Proof-of-Possession)

- RFC 9449 uyumlu
- Finansal islemler ve yuksek guvenlik modunda zorunlu
- Client ephemeral key pair uretir (ES256)
- Her request'te DPoP proof JWT gonderir: `htm`, `htu`, `jti`, `iat`
- Access token'a `cnf.jkt` claim'i eklenir (public key thumbprint)
- Resource server hem token'i hem DPoP proof'u dogrular
- Token calintisi durumunda private key olmadan kullanilamaz

### 4.4 Key Rotation

- 90 gunde bir asymmetric key rotation (PCI DSS, SOC 2)
- Yeni public key JWKS endpoint'ine eklenir (eski + yeni birlikte listelenir)
- Grace period: Client'lar JWKS cache'ini yeniler
- Eski key imzalamayi durdurur ama dogrulama icin kalir
- `retirement_time + max_token_lifetime + buffer` sonra eski key kaldirilir
- Her JWT'de `kid` header'i hangi key ile imzalandigini belirtir
- Cloud KMS (AWS KMS / GCP KMS) ile HSM-backed key storage

### 4.5 Custom Token

- Server SDK ile ozel token uretimi: `auth.admin.createCustomToken(uid, claims)`
- Client bu token'i exchange ederek access + refresh token alir
- Backend-to-backend senaryolari icin

---

## 5. Session Yonetimi

### 5.1 Session Politikalari (NIST 800-63B-4, Agustos 2025)

| Politika | Deger | Standart | Not |
|----------|-------|----------|-----|
| AAL1 idle timeout | Gereksinim yok | NIST 800-63B-4 | Rev 4'te AAL1 icin idle timeout zorunlulugu yok |
| AAL1 absolute timeout | SHALL var, SHOULD 30 gun | NIST 800-63B-4 Sec 2.1.3 | Mutlaka bir absolute timeout OLMALI (SHALL), deger SHOULD 30 gun |
| AAL2 idle timeout | SHOULD 1 saat | NIST 800-63B-4 | Rev 3'te 30dk idi, Rev 4'te 1 saate cikti ve SHALL->SHOULD oldu |
| AAL3 idle timeout | SHOULD 15dk | NIST 800-63B-4, PCI DSS 8.2.8 | Deger ayni, normatif keyword Rev 4'te SHALL->SHOULD |
| AAL2 absolute timeout | SHOULD 24 saat | NIST 800-63B-4 | Rev 3'te 12 saat idi, Rev 4'te 24 saate cikti |
| AAL3 absolute timeout | SHALL 12 saat | NIST 800-63B-4 | Degismedi |
| Auth code/OTP omru | Max 5dk | PSD2 RTS | |
| Concurrent session limiti | Yapilandirilabilir | SOC 2 best practice | |

> **SHALL vs SHOULD**: SHALL = zorunlu, SHOULD = strongly recommended. Rev 4'te AAL2 timeout'lari SHOULD'a gecti — esneklik sagliyor ama uygulamayı oneririz.

### 5.2 Session Ozellikleri

- Session'a device metadata baglama: IP, user-agent, device fingerprint
- Aktif session listesi: Kullanici tum aktif session'larini gorebilir (cihaz, konum, son aktivite)
- Uzaktan session sonlandirma: Kullanici herhangi bir session'i kapatabilir
- Session regeneration: Privilege escalation sonrasi yeni session ID
- Trusted device registry: "Bu cihazi hatirla" — device token ile tekrar MFA sorulmaz
- Session transfer: Cihazlar arasi session aktarimi (QR code ile)

### 5.3 Device Fingerprinting

- Sinyaller: user-agent, screen resolution, timezone, WebGL renderer, canvas hash, audio context, hardware concurrency
- Fingerprint hash session'a bind edilir
- Her request'te karsilastirilir
- Degisiklik = anomali flag'i -> step-up auth veya session sonlandirma

### 5.4 Anomaly Detection

- **Impossible travel**: Ardisik login'ler arasindaki mesafe/zaman orani (>500mph = flag)
- **IP degisimi**: Session icinde IP degisikligi
- **Device fingerprint drift**: Session icinde cihaz ozellikleri degisimi
- **Unusual time**: Normal saat disinda erisim
- **Velocity check**: Kisa surede cok fazla islem
- Her anomali icin risk skoru hesaplanir -> esik degerine gore aksiyon

---

## 6. Device Attestation & Binding

### 6.1 Android — Google Play Integrity API

```
Client App -> Play Integrity API -> Google Server -> Encrypted Verdict Token
                                                          |
Auth Server <- Decrypted Verdict <- Google Server <- Verdict Token
```

**Verdict degerlendirme:**
- `MEETS_STRONG_INTEGRITY` -> Tam guven (gercek cihaz + guncel yamalar)
- `MEETS_DEVICE_INTEGRITY` -> Yuksek guven (gercek, sertifikali cihaz)
- `MEETS_BASIC_INTEGRITY` -> Orta guven (bootloader acik olabilir)
- `MEETS_VIRTUAL_INTEGRITY` -> Emulator (izin verilebilir veya reddedilebilir)
- Bos -> Red (root'lu, hook'lu, sahte)

**Ek kontroller:**
- `appRecognitionVerdict`: Uygulamanin Play Store'dan yuklendigini dogrular
- `recentDeviceActivity`: Cihazin ne kadar aktif oldugunu gosterir (abuse tespiti)
- `playProtectVerdict`: Zararli yazilim kontrolu

### 6.2 iOS — Apple App Attest

1. Secure Enclave'de ECDSA P-256 key pair uretilir (private key cihazdan cikmaz)
2. `attestKey(keyId, clientDataHash)` ile Apple attestation object uretir
3. Server 9 adimli dogrulama yapar:
   - x5c sertifika zinciri -> Apple Root CA
   - Nonce dogrulama (authData + challenge hash)
   - Public key hash = keyId kontrolu
   - rpIdHash = SHA256(teamID + "." + bundleID)
   - signCount = 0 kontrolu (attestation'da)
   - aaguid kontrolu (prod vs dev)

**Assertion (sonraki request'ler):**
- Her request Secure Enclave private key ile imzalanir
- Server stored public key ile dogrular
- signCount artisini kontrol eder (clone detection)

### 6.3 Emulator / Root / Jailbreak Tespiti

**Android:**
- `su` binary, Magisk, KernelSU varligi
- Frida tespiti (port 27042, frida-server process)
- Xposed framework tespiti
- Build tags "test-keys" kontrolu
- Eksik hardware sensorleri
- Pil anomalileri (her zaman %50)
- RASP (Runtime Application Self-Protection) entegrasyonu

**iOS:**
- Cydia, Sileo, checkra1n path'leri
- Sandbox disina yazma yetenegi testi
- DYLD injection tespiti
- Fork() davranisi kontrolu
- URL scheme kontrolleri (cydia://)

### 6.4 Cryptographic Device Binding

**Kayit (Enrollment):**
1. Kullanici ilk kez dogrulanir (email + MFA)
2. Cihaz hardware enclave'de key pair uretir (iOS Secure Enclave / Android Keystore StrongBox)
3. Platform attestation ile key'in gercek donanim icinde uretildigi kanitlanir
4. Public key + cihaz metadata -> server'a gonderilir, kullanici hesabina baglanir

**Kullanim (Ongoing):**
1. Client request payload'u olusturur
2. Private key (hardware enclave icinde) payload'u imzalar (ECDSA ES256)
3. Request icerir: device ID + signature + payload
4. Server stored public key ile dogrular, cihaz durumunu ve risk sinyallerini kontrol eder

---

## 7. Transaction Authorization (PSD2/PSD3 SCA)

### 7.1 Dynamic Linking

**Zorunluluk (RTS Article 5):**
1. Odeme yapan kisi **tutar + aliciyi** gormeli
2. Auth kodu **tutar + aliciya spesifik** olmali
3. Tutar veya alici degisirse auth kodu gecersiz olmali
4. Islemin gizliligi, dogrulugu ve butunlugu korunmali

**Kriptografik baglama (asimetrik imza):**
```
challenge = server_nonce || amount || payee_id || timestamp
signature = Sign(private_key_in_TEE, SHA256(challenge))
```

- Private key cihazin Secure Element'inde
- Imza, spesifik tutar + aliciya bagli
- Tutar/alici degisirse imza gecersiz
- Server stored public key ile dogrular

### 7.2 Secure Payment Confirmation (SPC)

- WebAuthn ceremony'sinde transaction detaylari challenge'a encode edilir
- Kullanici biometric ile passkey'i acar
- Sonuc imza kriptografik olarak transaction detaylarina bagli
- PSD3 icin tercih edilen yaklasim

### 7.3 Transaction Akisi

```
1. Client -> "100 EUR, Alice'e transfer" -> Auth Server
2. Auth Server -> challenge olusturur (nonce + amount + payee) -> Client
3. Client -> kullaniciya gosterir "100 EUR -> Alice" (WYSIWYS)
4. Client -> TEE'de imzalar -> signed challenge -> Auth Server
5. Auth Server -> imza dogrular + device attestation kontrol
6. Auth Server -> blocking hook: before.transaction.approve -> App Backend
7. App Backend -> {allow: true} veya {deny: true, reason: "insufficient_funds"}
8. Auth Server -> Client'a sonuc doner
```

---

## 8. Blocking Pipeline & Hook Sistemi

### 8.1 Pipeline Mimarisi

Auth server, islem tamamlamadan once app backend'e danisir. Backend "tamam" demeden hicbir islem tamamlanmaz.

```
Client SDK              Auth Server                 App Backend
    |                       |                           |
    |--signUp(email,pw)--->|                           |
    |                       |--credentials dogrula----->|(internal)
    |                       |                           |
    |                       |--POST /hooks/endpoint---->|
    |                       |   {event, user, meta}     |
    |                       |   Headers:                |
    |                       |     webhook-id            |
    |                       |     webhook-timestamp     |
    |                       |     webhook-signature     |
    |                       |                           |
    |                       |<-- {verdict: "allow"} ----|  (backend user olusturdu)
    |                       |    VEYA                   |
    |                       |<-- {verdict: "deny",  ----|  (reddetti)
    |                       |     reason: "..."}        |
    |                       |                           |
    |<--token VEYA error---|                           |
```

### 8.2 Hook Tipleri

**Blocking Hooks (Senkron):**
Pipeline'i durdurur, backend'den cevap bekler.

| Hook | Tetikleme | Kullanim Senaryosu |
|------|-----------|---------------------|
| `before.user.create` | Signup oncesi | Backend'de kullanici olusturma, ban kontrolu |
| `before.login` | Her login denemesinde | IP/cihaz kontrolu, ozel business logic |
| `before.token.issue` | Token uretilmeden once | Custom claims ekleme, tenant kontrolu |
| `before.mfa.verify` | MFA dogrulama oncesi | Ek guvenlik kontrolleri |
| `before.password.reset` | Sifre sifirlama oncesi | Identity verification |
| `before.social.link` | Sosyal hesap baglama oncesi | Duplikat kontrolu |
| `before.transaction.approve` | Finansal islem onayi oncesi | Bakiye kontrolu, fraud detection |

**Non-Blocking Hooks (Asenkron):**
Pipeline'i durdurmaz, bilgilendirme amacli.

| Hook | Tetikleme | Kullanim Senaryosu |
|------|-----------|---------------------|
| `after.user.create` | Signup sonrasi | Welcome email, CRM sync |
| `after.login` | Basarili login sonrasi | Analytics, session log |
| `after.logout` | Logout sonrasi | Cleanup |
| `after.password.change` | Sifre degisikligi sonrasi | Bildirim |
| `after.mfa.enroll` | MFA aktiflestirilmesi sonrasi | Bildirim |
| `after.transaction.approve` | Islem onayi sonrasi | Receipt, bildirim |

### 8.3 Hook Guvenligi

- **Bidirectional signing**: Auth server hook'u HMAC-SHA256 ile imzalar, backend response'u imzalar
- **Replay korumasi**: `webhook-id` + `webhook-timestamp` ile (Standard Webhooks spec)
- **Timeout**: 10-20sn, asarsa yapilandirilabilir davranis
- **Failure mode**: Configurable — "deny on failure" (guvenli varsayilan) veya "allow on failure" (uptime oncelikli)
- **Retry**: Blocking hook'larda retry yok (timeout = failure mode davranisi). Non-blocking hook'larda exponential backoff ile retry

### 8.4 Hook Payload Formati

```json
{
  "event": "before.user.create",
  "timestamp": "2026-03-30T12:00:00Z",
  "request_id": "req_abc123",
  "user": {
    "id": "usr_xyz",
    "email": "user@example.com",
    "email_verified": true,
    "auth_method": "password",
    "metadata": {}
  },
  "context": {
    "ip": "1.2.3.4",
    "user_agent": "...",
    "device_fingerprint": "fp_...",
    "geo": { "country": "TR", "city": "Istanbul" },
    "risk_score": 0.15
  },
  "tenant": {
    "id": "tenant_abc",
    "name": "MyApp"
  }
}
```

**Beklenen response:**
```json
{
  "verdict": "allow",
  "metadata": { "db_user_id": "123" },
  "custom_claims": { "role": "admin" }
}
```

veya:

```json
{
  "verdict": "deny",
  "reason": "user_banned",
  "message": "Account suspended"
}
```

---

## 9. Risk Engine (Adaptive Authentication)

### 9.1 Risk Sinyalleri

| Sinyal | Kaynak | Agirlik |
|--------|--------|---------|
| Device fingerprint degisimi | Client SDK | Yuksek |
| Impossible travel | IP geolocation | Yuksek |
| IP reputation (VPN/Tor/proxy) | IP intelligence DB | Orta-Yuksek |
| Basarisiz login gecmisi | Auth server DB | Orta |
| Bilinmeyen cihaz | Device registry | Orta |
| Olagan disi saat | Kullanici profili | Dusuk-Orta |
| Request velocity | Rate limiter | Orta |
| Bot skoru | Bot detection modulu | Yuksek |
| Device attestation sonucu | Play Integrity / App Attest | Yuksek |

### 9.2 Risk Skorlama

- 0.0 - 1.0 arasi numerik skor
- Tum sinyaller agirlikli olarak birlestirilir
- Skor blocking hook payload'unda `context.risk_score` olarak iletilir
- Tenant'lar esik degerlerini yapilandirabilir

### 9.3 Risk-Based Aksiyonlar

| Risk Skoru | Aksiyon |
|------------|---------|
| 0.0 - 0.3 | Allow (normal akis) |
| 0.3 - 0.6 | Step-up auth (MFA challenge) |
| 0.6 - 0.8 | Siki step-up (hardware key / biometric zorunlu) |
| 0.8 - 1.0 | Block + kullaniciya bildirim + admin alert |

### 9.4 Pluggable Connector'lar

Ucuncu parti risk sinyali entegrasyonlari:
- Fingerprint (device intelligence)
- IPinfo / MaxMind (IP geolocation & reputation)
- Arkose Labs (bot detection)
- BreachSense / SpyCloud (credential monitoring)

---

## 10. Bot Detection

### 10.1 Built-in: Proof-of-Work Challenge

- Self-hostable, privacy-preserving (ALTCHA modeli — MIT lisans, ~30KB widget)
- Client kriptografik puzzle cozer (SHA-256, configurable difficulty via `maxnumber`)
- Insan dogrulama gerektirmez, cihaz CPU'su ile dogrulama
- GDPR uyumlu (cookie yok, fingerprint yok, tracking yok)
- **Tek basina yeterli DEGIL**: CAPTCHA-solving servisleri (2Captcha, CapMonster) ALTCHA cozebiliyor. PoW, savunma stackinin bir katmani olmali — rate limiting, IP reputation, account lockout ve risk engine ile birlikte kullanilmali

### 10.2 Pluggable Entegrasyonlar

- Cloudflare Turnstile
- hCaptcha
- Arkose Labs
- GeeTest

### 10.3 Behavioral Signals

- Request timing analizi
- Mouse/touch pattern analizi (client SDK uzerinden)
- Keystroke dynamics (opsiyonel, risk engine'e sinyal olarak)

---

## 11. Account Recovery

### 11.1 Recovery Yontemleri

1. **Recovery codes**: Kayit sirasinda 10 adet tek kullanimlik kod uretilir (256-bit random, base32 encoded). Argon2id ile hash'lenip saklanir.

2. **Trusted contacts** (N-of-M): Kullanici 3-5 guvenilir kisi belirler. Recovery icin M kisi (orn 2/3) onay vermeli. Google Recovery Contacts modeli.

3. **Recovery passkey**: Ikinci bir cihaza kayitli yedek passkey. "Recovery" flag'i ile isaretlenir.

4. **Admin-assisted recovery**: Admin panelinden identity verification sonrasi manual recovery. Tam audit trail ile loglanir.

5. **Email recovery**: Dogrulanmis email adresine magic link. Sadece dusuk guvenlik seviyesindeki hesaplar icin.

### 11.2 Recovery Kurallari

- Recovery islemi asla MFA'yi es gecmeden tamamlanamaz (esdeger guvenlik seviyesi gerekli)
- Tum recovery islemleri audit log'a yazilir
- Recovery sonrasi tum mevcut session'lar sonlandirilir
- Recovery sonrasi yeni MFA enrollment zorunlu

---

## 12. Organization & Team Management (B2B)

### 12.1 Organization Yapisi

```
Organization
  |-- Members (Owner > Admin > Member + custom roller)
  |-- SSO Connections (SAML / OIDC per org)
  |-- API Keys (org-scoped)
  |-- Audit Logs (org-scoped)
  |-- Settings (auth yontemleri, MFA politikasi, session timeout)
```

### 12.2 Ozellikler

- **Roller & Izinler**: Hiyerarsik roller (Owner > Admin > Member) + max 20 custom rol per org. Izinler spesifik aksiyonlar, roller izin koleksiyonlari.
- **Davet sistemi**: Email ile davet + rol atama. Mevcut ve yeni kullanicilar icin calisir. Davet token'i 7 gun gecerli.
- **Domain verification**: Email domain dogrulama ile otomatik org'a ekleme (admin onayi opsiyonel)
- **Enterprise SSO per org**: SAML 2.0 veya OIDC baglantilari org bazinda yapilandirilir. Self-service SSO kurulum paneli.
- **SCIM 2.0 provisioning**: Harici IdP'lerden otomatik kullanici ekleme/cikarma. Per-org SCIM endpoint.
- **Delegated admin**: Org admin'leri kendi kullanicilarini yonetir, platform seviyesinde erisim gerekmez.
- **Org-level audit logs**: Her org kendi audit log'larini gorebilir.

---

## 13. API Key & M2M Authentication

### 13.1 API Key'ler

- Kullanici veya organization-scoped
- Uzun omurlu opaque token'lar
- Granular permission scope'lari (ornek: `read:users`, `write:users`)
- Olusturma, listeleme, iptal etme UI/API
- SHA-256 hash olarak saklanir (plaintext saklanmaz)
- Rate limit per key

### 13.2 M2M (Machine-to-Machine) Tokens

- OAuth 2.0 client_credentials flow
- Client ID + Client Secret -> kisa omurlu JWT
- Organization-scoped
- `org_id` claim'i icinde

### 13.3 Personal Access Tokens (PATs)

- Kullanici tarafindan olusturulan programmatic erisim token'lari
- Scope'lu, sureli
- GitHub PAT modeli

---

## 14. Admin Impersonation

### 14.1 Mekanizma

- RFC 8693 Token Exchange ile impersonation token uretilir
- Token'da hem `actor` (admin) hem `subject` (hedef kullanici) claim'leri bulunur
- Tum aksiyonlar audit log'da `impersonated: true` flag'i ile isaretlenir

### 14.2 Kurallar

- Sadece belirli izne sahip admin'ler impersonate edebilir
- Max sure: yapilandirilabilir (varsayilan 1 saat)
- Impersonate edilen kullaniciya bildirim (opsiyonel, tenant yapilandirilabilir)
- Impersonation session'inda hassas islemler (sifre degistirme, MFA degisikligi) yapilamaz

---

## 15. Multi-Tenancy

### 15.1 Izolasyon Modeli

Her tenant icin tam izolasyon:
- Ayri user pool
- Ayri auth yontemi konfigurasyonu
- Ayri SSO baglantilari
- Ayri rate limit'ler ve kotalar
- Ayri audit log'lar
- Ayri webhook endpoint'leri
- Ayri branding (logo, renkler, email template'leri)

### 15.2 Custom Domain

- Tenant basina ozel domain: `auth.myapp.com`
- Otomatik TLS sertifikasi (Let's Encrypt / ACME)
- Wildcard sertifika destegi

### 15.3 White-Label

- Login/register sayfalari tenant branding'i ile
- Email template'leri tenant'a ozel
- SMS icerikleri tenant'a ozel
- Hata mesajlari tenant diline gore

---

## 16. Audit Logging

### 16.1 Loglanan Olaylar

**Authentication:**
- `auth.login.success`, `auth.login.failure`
- `auth.logout`
- `auth.signup`
- `auth.password.change`, `auth.password.reset.request`, `auth.password.reset.complete`

**MFA:**
- `mfa.enroll`, `mfa.challenge`, `mfa.verify.success`, `mfa.verify.failure`
- `mfa.remove`

**Session:**
- `session.create`, `session.refresh`, `session.revoke`
- `session.anomaly`

**Token:**
- `token.issue`, `token.refresh`, `token.revoke`

**Account:**
- `user.create`, `user.update`, `user.delete`
- `user.email.verify`, `user.phone.verify`
- `social.link`, `social.unlink`
- `recovery.initiate`, `recovery.complete`

**Admin:**
- `admin.user.create`, `admin.user.update`, `admin.user.delete`
- `admin.impersonate.start`, `admin.impersonate.end`
- `admin.config.change`
- `admin.key.rotate`

**Transaction:**
- `transaction.approve.request`, `transaction.approve.success`, `transaction.approve.failure`

### 16.2 Log Formati

```json
{
  "event_id": "<UUIDv7>",
  "trace_id": "<request correlation ID>",
  "timestamp_ms": 1711800000000,
  "event_type": "auth.login.success",
  "actor": {
    "id": "usr_xyz",
    "type": "user",
    "ip": "1.2.3.4",
    "user_agent": "...",
    "device_fingerprint": "fp_...",
    "geo": { "country": "TR", "city": "Istanbul" }
  },
  "target": {
    "type": "session",
    "id": "sess_abc"
  },
  "result": "success",
  "auth_method": "password+totp",
  "risk_score": 0.12,
  "tenant_id": "tenant_abc",
  "metadata": {},
  "prev_hash": "<SHA-256 of previous event>",
  "event_hash": "<SHA-256 of prev_hash + canonical(event_core)>"
}
```

### 16.3 Tamper-Evident (Kurcalamaya Dayanikli) Log Zinciri

- SHA-256 hash chain: Her event onceki event'in hash'ini icerir
- Herhangi bir log degistirilirse zincir kirilir -> tespit edilir
- Canonical JSON serialization (key'ler alfabetik sirali)
- Dogrulama: O(n) — tum zincir basla tekrar hesapla
- **Hash chain CIPHERTEXT uzerinden hesaplanir, plaintext degil** — boylece cryptographic erasure (DEK silme) hash chain'i BOZMAZ. Ciphertext byte'lari degismedigi icin zincir dogrulanabilir kalir
- Her erasure islemi icin `ERASURE` event tipi loglanir (hangi entry'ler etkilendi)
- Non-PII metadata (timestamp, event_type, action code) plaintext kalir — erasure sonrasi entry'ler kismi okunabilir

### 16.4 GDPR Uyumu (Cryptographic Erasure)

Kisisel veri alanlari per-user encryption key ile sifrelenir:
```
log_entry.actor.ip = AES-GCM(user_key_123, "1.2.3.4")
log_entry.actor.id = AES-GCM(user_key_123, "usr_xyz")
```

Silme talebi geldiginde:
- `user_key_123` silinir
- Log entry'leri desifre edilemez hale gelir
- Log zinciri bozulmaz (hash'ler ayni kalir)
- GDPR Art. 17 karsilanir, SOC 2 audit butunlugu korunur

### 16.5 Saklama Politikasi

- Auth/authz/incident loglari: minimum 12 ay (SOC 2 beklentisi)
- 90 gun readily searchable
- Sonrasi cold storage (S3 Glacier, vb.)
- Tenant bazinda yapilandirilabilir retention suresi

---

## 17. Sifreleme & Key Management

### 17.1 Data at Rest

- **Algoritma**: AES-256-GCM (authenticated encryption)
- **Yontem**: Envelope encryption
  - KEK (Key Encryption Key): HSM/Cloud KMS'te saklanir
  - DEK (Data Encryption Key): Her kayit icin ayri, KEK ile sifrelenir
  - KEK rotate edildiginde sadece DEK'ler re-wrap edilir, veri yeniden sifrelenmez

### 17.2 Data in Transit

- **Minimum**: TLS 1.2 (PCI DSS zorunlu)
- **Tercih**: TLS 1.3
- **Yasak**: SSLv3, TLS 1.0, TLS 1.1
- mTLS: Server-to-server iletisimde opsiyonel (confidential client'lar icin)

### 17.3 Password Hashing

```
final_hash = Argon2id(
  password = HMAC-SHA256(pepper, raw_password),
  salt = crypto.randomBytes(16),
  m = 65536,  // 64MB
  t = 3,
  p = 1
)
```

- Pepper HSM/KMS'te, DB'de degil
- Salt her password'a unique
- Target hash suresi: ~300ms

### 17.4 Sifrelenecek Veriler

- TOTP secret'lari
- Refresh token'lar (veya hash olarak sakla)
- PII (email, telefon, isim)
- Backup/recovery kodlari
- Device binding key'leri
- Webhook secret'lari

### 17.5 Key Ceremony (SOC 2 / PCI DSS)

- Split knowledge: Master key parcalara ayrilir, her parca farkli custodian'da
- Dual control: Min 2 yetkili kisi her key operasyonu icin
- Quorum: 3-of-5 model (Shamir's Secret Sharing)
- Dokumantasyon: Her islem loglanir, imzalanir, video kaydedilir
- Frekans: Yillik + HSM degisikligi + custodian degisikligi + compromise suphesi

---

## 18. Rate Limiting & Anti-Abuse

### 18.1 Rate Limit Katmanlari

| Katman | Kapsam | Algoritma |
|--------|--------|-----------|
| Global | Tum trafik | Token bucket |
| Per-IP | IP adresi basina | Sliding window |
| Per-user | Kullanici basina | Sliding window |
| Per-device | Device fingerprint basina | Sliding window |
| Per-endpoint | Endpoint basina | Sliding window |
| Per-tenant | Tenant basina | Token bucket |

### 18.2 Endpoint Bazinda Limitler

| Endpoint | Limit | Pencere |
|----------|-------|---------|
| POST /auth/login | 10 | 5dk |
| POST /auth/signup | 5 | 15dk |
| POST /auth/otp/verify | 5 | 5dk |
| POST /auth/password/reset | 3 | 15dk |
| POST /auth/magic-link | 1 | 5dk |
| GET /auth/token/refresh | 30 | 1dk |

### 18.3 Dagitik Rate Limiting (Redis)

- Redis Sorted Set + Lua script ile atomic sliding window
- Race condition'a karsi Lua EVAL ile atomik islem
- Rate limit header'lari: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `Retry-After`

### 18.4 IP Reputation & Geo-blocking

- VPN/Tor/proxy tespiti (IPinfo, MaxMind)
- Ulke bazli beyaz/kara liste (tenant yapilandirilabilir)
- Impossible travel detection: Haversine formula ile mesafe, hiz hesabi

---

## 19. Webhook & Event Streaming

### 19.1 Webhook Sistemi

- Tenant'lar endpoint URL'leri register eder
- Event bazinda subscribe (ornek: sadece `user.created` ve `auth.login.success`)
- Fan-out: Ayni event birden fazla endpoint'e gonderilebilir

### 19.2 Webhook Guvenligi

- HMAC-SHA256 imza (Standard Webhooks spec)
- Header'lar: `webhook-id`, `webhook-timestamp`, `webhook-signature`
- Idempotency key: Her event'te unique `event_id`

### 19.3 Retry Politikasi

- Exponential backoff with jitter
- 5xx -> retry (max 5 deneme: 1dk, 5dk, 30dk, 2sa, 24sa)
- 4xx -> dead letter queue (DLQ), retry yok
- Timeout: 30sn

### 19.4 Dead Letter Queue & Replay

- Basarisiz event'ler DLQ'ya gider
- Admin panelinden DLQ goruntulenebilir
- Manuel veya otomatik replay
- Belirli timestamp'ten itibaren event replay

---

## 20. OpenID Connect Provider

Auth server bir OpenID Connect Provider olarak calisir.

### 20.1 Desteklenen Ozellikler

- Discovery: `/.well-known/openid-configuration`
- Authorization Code + PKCE flow
- Token endpoint (token exchange)
- UserInfo endpoint
- JWKS endpoint
- Dynamic client registration (RFC 7591/7592)
- Front-channel & back-channel logout
- PAR (Pushed Authorization Requests) — FAPI 2.0 zorunlu

### 20.2 Hedeflenen OpenID Sertifikasyon Profilleri

- Basic OP
- Config OP
- Dynamic OP
- Form Post OP
- FAPI 2.0 Security Profile
- Logout profilleri (RP-Initiated, Session, Front-Channel, Back-Channel)

---

## 21. AI Agent & MCP Authentication

### 21.1 Machine Client Entity

- Kullanici ve service account'larin yaninda "agent" entity tipi
- OAuth 2.1 client credentials ile dogrulama
- Scoped permission'lar

### 21.2 Token Exchange (RFC 8693)

- Agent'lar kullanici adina islem yapabilir (delegation)
- Token exchange ile kullanici token'i agent token'ina donusturulur
- `act` claim'i ile asil calisan agent belirtilir
- `may_act` claim'i ile delegation sinirlari tanimlanir

### 21.3 MCP Server Uyumu (Kasim 2025 spec revizyonu)

- OAuth 2.1 + PKCE zorunlu — "PKCE is REQUIRED for all clients" (Implementation Req #2)
- MCP server'lar **OAuth Resource Server** olarak siniflandirilir (Haziran 2025+)
- Protected Resource Metadata (RFC 9728) yayinlanir — authorization server'i deklare eder
- **Client ID Metadata Documents (CIMD)**: Dynamic Client Registration yerine DNS-based trust modeli — client JSON dokumani kontrol ettigi URL'de yayinlar
- RFC 8693 token exchange MCP core spec'te zorunlu degil ama downstream erisim icin **onerilen pattern**

**Takip edilecek IETF draft'lari:**
- `draft-klrc-aiagent-auth-00` (Mart 2026): Agent'lari workload olarak tanimlar
- `draft-oauth-ai-agents-on-behalf-of-user-00`: Kullanici-agent delegasyonu
- `draft-ni-wimse-ai-agent-identity-02`: Workload identity mimarisi

---

## 22. Decentralized Identity (DID / Verifiable Credentials)

### 22.1 EUDI Wallet Destegi

- eIDAS 2.0: **6 Aralik 2026**'ya kadar uye devletler en az bir EUDI Wallet sunmali + kamu kurumlari ve VLOP'lar kabul etmeli (uygulama kanunlarindan 24 ay sonra, 4 Aralik 2024 tarihli ilk batch)
- **Aralik 2027 sonu**: Bankacilik, telekom, saglik sektorleri EUDI Wallet'i kabul etmek ZORUNDA (36 ay sonra)
- Not: Bazi uye devletler (Hollanda, Bulgaristan) gecikme sinyali verdi. Ek uygulama kanunlari hala danisma surecinde (Mart 2026 itibariyle). ARF v2.7.3
- Teknik stack: OpenID for Verifiable Credentials (OID4VCI/OID4VP) + SD-JWT VC

### 22.2 Auth Server Rolu

- **Verifier** olarak calisir: EUDI Wallet'lardan credential kabul eder
- OpenID4VP (Verifiable Presentations) ile credential dogrulama
- Selective disclosure destegi: "18 yasindan buyuk" bilgisi alinir, dogum tarihi alinmaz

---

## 23. Breach Detection & Credential Monitoring

### 23.1 Compromised Password Kontrolu

- Kayit ve sifre degisikliginde HaveIBeenPwned k-Anonymity API kontrolu (NIST 800-63B zorunlu)
- SHA-1 hash'in ilk 5 karakteri gonderilir, eslesen hash listesi doner
- Client-side ve server-side cift kontrol

### 23.2 Credential Monitoring

- Dark web monitoring API entegrasyonu (BreachSense, SpyCloud, Enzoic)
- Yeni breach'lerde etkilenen kullanicilara bildirim
- Zorunlu sifre sifirlama veya step-up auth

### 23.3 Credential Stuffing Tespiti

- Cok sayida farkli hesaba ayni IP/fingerprint'ten login denemesi
- Otomatik IP/fingerprint bloklama
- Risk engine'e sinyal olarak iletilir

---

## 24. Compliance Automation

### 24.1 GDPR Data Subject Requests

- `GET /admin/users/:id/export` — Kullanici verisini JSON olarak export
- `DELETE /admin/users/:id` — Kullanici verisini sil + log'lari cryptographic erasure
- `GET /admin/users/:id/consents` — Consent gecmisi
- `POST /admin/users/:id/consents` — Consent kaydi

### 24.2 Data Retention

- Yapilandirilabilir retention suresi (tenant bazinda)
- Otomatik purging (sifreleme key'i silme ile)
- Retention suresi dolan veriler otomatik temizlenir

### 24.3 Compliance Raporlari

- Login basari/basarisizlik istatistikleri
- MFA adoption oranlari
- Password age dagilimi
- Session anomali raporlari
- Audit log export (compliance-friendly format)

---

## 25. Edge SDK

### 25.1 Amac

Cloudflare Workers, Vercel Edge, Deno Deploy gibi edge runtime'larda JWT dogrulama.

### 25.2 Ozellikler

- JWKS fetching + caching
- JWT signature verification
- Claims validation
- DPoP proof verification
- <50KB bundle size
- Sifir network round-trip (JWT self-contained dogrulama)

---

## 26. SDK Tasarimi

### 26.1 Client SDK (`@authserver/client`)

```typescript
// Initialization
const auth = createAuthClient({
  url: 'https://auth.myapp.com',
  apiKey: 'pk_live_...'
});

// Email + Password
await auth.signUp({ email, password });
await auth.signIn({ email, password });

// OTP
await auth.signInWithOtp({ email });
await auth.verifyOtp({ email, code });

// Social Login
await auth.signInWithOAuth({ provider: 'google' });          // Web: redirect/popup
await auth.signInWithCredential({ provider, token });         // Mobile: native token

// Magic Link
await auth.signInWithMagicLink({ email });

// Passkeys
await auth.signInWithPasskey();
await auth.registerPasskey();

// MFA
await auth.mfa.enroll({ method: 'totp' });                   // QR code doner
await auth.mfa.challenge();
await auth.mfa.verify({ code });

// Step-Up Auth
await auth.stepUp({ method: 'passkey' });

// Transaction Approval (PSD2 SCA)
await auth.transaction.approve({ amount: 100, currency: 'EUR', payee: 'Alice' });

// Session
await auth.signOut();
await auth.getSession();
await auth.getUser();
auth.onAuthStateChange((event, session) => { ... });

// Device
await auth.device.register();                                  // Device binding
await auth.device.attest();                                    // Platform attestation

// Recovery
const codes = await auth.recovery.generateCodes();
await auth.recovery.useCode(code);
```

### 26.2 Server SDK (`@authserver/server`)

```typescript
// Initialization
const auth = createAuthServer({
  url: 'https://auth.myapp.com',
  serviceKey: 'sk_live_...'
});

// Token Verification
const user = await auth.verifyToken(jwt);

// Admin Operations
await auth.admin.createUser({ email, password });
await auth.admin.updateUser(uid, { email_verified: true });
await auth.admin.deleteUser(uid);
const users = await auth.admin.listUsers({ page: 1, limit: 20 });
await auth.admin.setCustomClaims(uid, { role: 'admin', plan: 'pro' });
await auth.admin.revokeAllSessions(uid);
const token = await auth.admin.createCustomToken(uid, { custom: 'data' });

// Impersonation
const impersonationToken = await auth.admin.impersonate(targetUid);

// Blocking Hooks
auth.hooks.before('user.create', async (event) => {
  const user = await db.users.create({ authId: event.user.id });
  return { allow: true, metadata: { dbUserId: user.id } };
});

auth.hooks.before('login', async (event) => {
  if (event.user.banned) return { deny: true, reason: 'banned' };
  return { allow: true };
});

auth.hooks.before('transaction.approve', async (event) => {
  const balance = await getBalance(event.user.id);
  if (balance < event.transaction.amount) {
    return { deny: true, reason: 'insufficient_funds' };
  }
  return { allow: true };
});

// Non-Blocking Events
auth.on('user.created', async (event) => {
  await sendWelcomeEmail(event.user.email);
  await crm.createContact(event.user);
});

auth.on('login.failed', async (event) => {
  await alerting.notify('login_failure', event);
});

// Organizations
await auth.orgs.create({ name: 'Acme Corp', domain: 'acme.com' });
await auth.orgs.addMember(orgId, userId, 'admin');
await auth.orgs.configureSso(orgId, { provider: 'saml', metadata_url: '...' });
```

### 26.3 Edge SDK (`@authserver/edge`)

```typescript
import { createVerifier } from '@authserver/edge';

const verifier = createVerifier({
  jwksUrl: 'https://auth.myapp.com/.well-known/jwks.json',
  issuer: 'https://auth.myapp.com',
  audience: 'my-app'
});

// Cloudflare Worker / Vercel Edge
export default {
  async fetch(request) {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const { valid, claims, error } = await verifier.verify(token);

    if (!valid) return new Response('Unauthorized', { status: 401 });

    // DPoP verification (optional)
    const dpopProof = request.headers.get('DPoP');
    if (dpopProof) {
      const dpopValid = await verifier.verifyDPoP(dpopProof, token, request);
      if (!dpopValid) return new Response('Invalid DPoP', { status: 401 });
    }

    return fetch(request);
  }
};
```

### 26.4 NestJS SDK (`@authserver/nestjs`)

```typescript
// Module Registration
@Module({
  imports: [
    AuthServerModule.register({
      url: 'https://auth.myapp.com',
      serviceKey: process.env.AUTH_SERVICE_KEY,
      hooks: {
        'before.user.create': BeforeUserCreateHandler,
        'before.login': BeforeLoginHandler,
        'before.transaction.approve': BeforeTransactionHandler,
      }
    })
  ]
})
export class AppModule {}

// Guard
@Controller('protected')
@UseGuards(AuthGuard)
export class ProtectedController {

  @Get('profile')
  @RequireAuth()                                // AAL1 yeterli
  getProfile(@CurrentUser() user: AuthUser) {}

  @Post('transfer')
  @RequireAuth({ acr: 'aal2', mfa: true })     // Step-up zorunlu
  transfer(@CurrentUser() user: AuthUser) {}

  @Post('high-value-transfer')
  @RequireAuth({ acr: 'aal3', dpop: true })    // Hardware key + DPoP zorunlu
  highValueTransfer(@CurrentUser() user: AuthUser) {}
}

// Hook Handler
@Injectable()
export class BeforeUserCreateHandler implements AuthHookHandler {
  constructor(private readonly userService: UserService) {}

  async handle(event: AuthHookEvent): Promise<AuthHookResponse> {
    const user = await this.userService.create({ authId: event.user.id });
    return { allow: true, metadata: { dbUserId: user.id } };
  }
}
```

---

## 27. Veritabani Semasi (Ozet)

### Core Tablolar

- `tenants` — Multi-tenant konfigurasyonu
- `users` — Kullanici profilleri (tenant-scoped)
- `identities` — Auth yontemleri (email, social, passkey — user has many)
- `credentials` — Password hash'leri, TOTP secret'lari (sifrelenmis)
- `sessions` — Aktif session'lar
- `refresh_tokens` — Opaque refresh token hash'leri + family tracking
- `devices` — Kayitli cihazlar + public key + attestation durumu
- `mfa_enrollments` — MFA kayitlari (TOTP, WebAuthn, SMS)
- `webauthn_credentials` — Passkey public key'leri + metadata
- `recovery_codes` — Recovery kodlari (Argon2id hash)
- `organizations` — B2B organizasyonlar
- `org_members` — Organizasyon uyelikleri + roller
- `org_sso_connections` — Per-org SSO konfigurasyonlari
- `api_keys` — API key hash'leri + scope'lar
- `oauth_clients` — Registered OAuth client'lar
- `audit_logs` — Tamper-evident log zinciri
- `webhook_subscriptions` — Webhook endpoint kayitlari
- `webhook_deliveries` — Webhook teslimat gecmisi + DLQ
- `hook_configs` — Blocking/non-blocking hook konfigurasyonlari
- `user_consents` — GDPR consent kayitlari

### Sifreleme

- PII alanlari (email, telefon, isim): AES-256-GCM, per-tenant DEK
- Credential alanlari (TOTP secret, recovery codes): AES-256-GCM, per-user DEK
- Audit log PII alanlari: AES-256-GCM, per-user DEK (cryptographic erasure icin)

---

## 28. Altyapi Gereksinimleri

### 28.1 Monorepo Yapisi

```
authserver/
  packages/
    server/          → NestJS auth server (core API, headless)
    dashboard/       → Next.js admin panel (self-hosted + SaaS ortak)
    client-sdk/      → @authserver/client (Web, React Native, Flutter)
    server-sdk/      → @authserver/server (Node.js backend SDK)
    edge-sdk/        → @authserver/edge (<50KB, Cloudflare/Vercel)
    nestjs-sdk/      → @authserver/nestjs (decorator-based)
    shared/          → Ortak tipler, validasyon, utils
  docker/
    docker-compose.yml    → Dev ortami (server + postgres + redis)
    Dockerfile.server     → Production server image
    Dockerfile.dashboard  → Production dashboard image
  helm/
    authserver/           → Kubernetes Helm chart
  docs/
    quickstart/           → Framework-bazli quickstart rehberleri
    api-reference/        → OpenAPI spec'ten otomatik uretim
```

### 28.2 Dashboard (Next.js)

Self-hosted'da da SaaS'ta da ayni dashboard kullanilir.

**Teknoloji:**
- Next.js 15 (App Router)
- shadcn/ui + Tailwind CSS
- React Query (server state)
- Auth server API'yi tuketir (kendi dogfood'u)

**Self-hosted'da:**
- Auth server ile ayni Docker Compose'da ayaga kalkar
- `http://localhost:3001` uzerinden erisim
- Ilk acilista setup wizard: admin hesap olustur, temel konfigurasyon

**Dashboard sayfalari:**
- Overview: MAU, login trendi, aktif session, alertler
- Users: liste, detay, ban, password reset, MFA reset, import/export
- Authentication: provider toggle, password policy, session policy
- Hooks & Webhooks: endpoint, test, loglar, DLQ
- Organizations (B2B): org, member, SSO, SCIM
- Audit Logs: real-time stream, filtre, export, integrity verify
- Security: risk engine, IP whitelist, geo-blocking, device attestation
- Analytics: auth method dagilim, MFA adoption, risk score
- Settings: domain, email/SMS provider, branding, CORS, i18n

### 28.3 Runtime

- **Framework**: NestJS (Node.js)
- **Veritabani**: PostgreSQL (primary), Redis (cache, rate limiting, session store)
- **Message Queue**: Redis Streams veya NATS (webhook delivery, async events)
- **KMS**: AWS KMS / GCP KMS / HashiCorp Vault (key management)

### 28.4 Self-Hosted Deployment

**Docker Compose (gelistirme + kucuk olcek):**
```bash
docker compose up -d
# authserver-api:    localhost:3000
# authserver-admin:  localhost:3001
# postgres:          localhost:5432
# redis:             localhost:6379
```

**Docker (production):**
```bash
docker run -d \
  --name authserver \
  -p 3000:3000 \
  -e DATABASE_URL=postgres://... \
  -e REDIS_URL=redis://... \
  -e ENCRYPTION_KEY=... \
  authserver/server:latest
```

**Kubernetes / Helm:**
```bash
helm install authserver authserver/authserver \
  --set database.url=postgres://... \
  --set redis.url=redis://... \
  --set dashboard.enabled=true
```

**Konfigurasyon:**
- Environment variables (12-factor app)
- Config file (YAML) opsiyonel
- Tum ayarlar dashboard veya API ile de degistirilebilir
- Ilk acilista setup wizard (admin hesap + temel konfigurasyon)

### 28.5 Guvenlik Altyapisi

- WAF (PCI DSS 6.4.2 zorunlu)
- DDoS korumasi
- Vulnerability scanning (aylik, PCI DSS ceyreklik)
- Penetration testing (yillik, PCI DSS zorunlu)
- SIEM entegrasyonu (log aggregation, alerting)

### 28.6 Monitoring & Alerting

- Brute force tespiti: 5-10 basarisiz login / 5dk -> alert
- Impossible travel: Cografi uzaklik / zaman orani -> alert
- Privilege escalation: Yeni admin hesap / yetki yukseltme -> alert
- Off-hours erisim: Is saatleri disinda hassas sistem erisimi -> alert
- Credential stuffing: Cok sayida farkli hesaba ayni IP'den deneme -> alert

---

## 29. PSD3 / PSR Hazirlik

Politik anlasma: 27 Kasim 2025. Resmi yayin: Q2 2026 bekleniyor. PSR dogrudan uygulanabilir regulation olarak 18-24 ay sonra yururluge girer (H2 2027 - basi 2028).

**Kritik yapisal degisiklik:** SCA kurallari artik PSD3'te degil, **PSR (Payment Services Regulation) Articles 85-89**'da. Dogrudan uygulanabilir regulation — ulkeler arasi tutarsiz transposition sorunu ortadan kalkiyor.

### Yeni SCA Gereksinimleri (PSR)

- **Iki inherence faktoru artik izinli** (Art. 85): Ornegin parmak izi + yuz tanima. Ancak SADECE inherence kategorisinde gecerli — iki possession veya iki knowledge YASAK
- **Genisletilmis SCA kapsami**: Login, mandate setup, cihaz recovery islemleri de SCA gerektiriyor
- **SCA erisilebirligi yasal hak**: Akilli telefon disinda yontemler sunulmak ZORUNDA
- **SCA delegasyonu = outsourcing**: Dokumantasyon ve denetim gereksinimleri artiyor
- **Impersonation fraud sorumlulugu**: PSP'ler artik impersonation fraud'dan da sorumlu
- Gercek zamanli fraud monitoring zorunlulugu
- API hardening gereksinimleri
- eIDAS 2.0 (EUDI Wallet) ile uyum

---

## 30. DORA (Digital Operational Resilience Act)

### 30.1 Nedir?

AB finansal sektoru icin dijital operasyonel dayaniklilik regülasyonu. **17 Ocak 2025'te tam olarak yururluge girdi.** Bankalar, sigorta sirketleri, yatirim firmalari ve onlarin **ICT ucuncu taraf hizmet saglayicilari** icin gecerli.

### 30.2 Bizi Neden Ilgilendiriyor?

Auth platformumuz banka musterilerine hizmet verdiginde **ICT ucuncu taraf hizmet saglayicisi** oluyoruz. DORA dogrudan bize uygulanir.

### 30.3 Gereksinimler

**Sozlesme gereksinimleri (Art. 28-30):**
- SLA'lar (uptime, response time, RTO/RPO)
- Cikis stratejisi (exit plan — musteri baska saglayiciya gecebilmeli)
- Denetim haklari (musteri veya regulator bizim sistemlerimizi denetleyebilmeli)
- Olay bildirimi (incident reporting — 24 saat icinde)
- Is surekliligi testi (business continuity testing)

**Teknik gereksinimler:**
- ICT risk management framework
- Incident classification ve reporting
- Digital operational resilience testing (TLPT — Threat-Led Penetration Testing)
- Ucuncu taraf risk yonetimi dokumantasyonu

**Cezalar:** Kritik ICT Ucuncu Taraf olarak tanimlanirsa, **gunluk dunya cirosunun %1'ine** kadar ceza.

### 30.4 Implementasyon

- DORA-compliant sozlesme template'leri hazirla
- SLA/SLO dokumantasyonu
- Incident response + reporting proseduru (24 saat)
- Exit/transition plani
- Denetim erisim mekanizmasi (read-only audit access)
- Is surekliligi test kanit raporu (6 aylik)
- Maliyet: €30K-€100K (dokumantasyon + prosedur)

---

## 31. FIPS 140-3 (Cryptographic Module Validation)

### 31.1 Nedir?

Kriptografik modullerin guvenligini dogrulayan ABD federal standardi. FIPS 140-2 **21 Eylul 2026'da** sunset oluyor, bundan sonra sadece FIPS 140-3 gecerli.

### 31.2 Self-Hosted icin Neden Ideal?

- **Urun-seviye sertifika** — deployment modeline bagli degil
- Platformun kendisi degil, **kullandigi kriptografik modul** validate edilir
- Validate edilmis kutuphane kullanarak platform FIPS-compliant olabilir
- Musteri kendi altyapisinda FIPS-validated binary deploy eder

### 31.3 Uygulama Stratejisi

**Yol 1: Validate edilmis kutuphane kullan (oneri)**
- OpenSSL FIPS module (validated)
- BoringCrypto (Go — Google tarafindan validated)
- Bouncy Castle FIPS (Java)
- Node.js icin: OpenSSL FIPS provider + `--enable-fips` flag

**Yol 2: Validation-as-a-Service (VaaS)**
- SafeLogic gibi saglayicilar pre-validated modulleri lisanslar
- Sure: ~2 ay (geleneksel 12-24 ay yerine)
- Maliyet: €50K-€150K (geleneksel €150K-€400K yerine)

### 31.4 FIPS Mode Konfigurasyonu

- FIPS mode tenant bazinda aktiflestirilir
- FIPS modunda sadece approved algoritmalar: AES-128/192/256, SHA-2, HMAC, RSA 2048+, ECDSA P-256/P-384, EdDSA
- Chacha20, MD5, SHA-1 (signing icin), RSA 1024 FIPS modunda YASAK
- Argon2id FIPS-approved degil — FIPS modunda PBKDF2-HMAC-SHA256 (600K+ iteration) kullanilir

---

## 32. ETSI TS 119 461 (Identity Proofing)

### 32.1 Nedir?

Trust service'ler icin kimlik dogrulama standardi. **Agustos 2027'de zorunlu** oluyor (EU Implementing Regulation 2025/1566).

### 32.2 Seviyeler

- **Baseline Level**: Temel kimlik dogrulama. Document verification + liveness check
- **Extended Level**: Guclendirilmis dogrulama. Yuz yuze veya esdeger remote verification

### 32.3 Senaryolar

- Yuz yuze (face-to-face) dogrulama
- Uzaktan destekli (remote assisted) — video call ile operator
- Gozetimsiz uzaktan (unattended remote) — AI-based document + liveness

### 32.4 Bizim Icin Anlami

- QTSP partnership yaptigimizda, QTSP zaten ETSI TS 119 461 uyumlu olmali
- Auth server olarak bizim rolumuz: KYC provider entegrasyonu (Onfido, Jumio, Veriff, Sumsub, IDnow — hepsi zaten sertifikali)
- Identity proofing hook'u: `before.identity.verify` blocking hook ile backend KYC sonucunu onaylayabilir

---

## 33. QES (Qualified Electronic Signature) Stratejisi

### 33.1 QTSP Partnerligi vs Kendi QTSP

| | QTSP Partnerligi | Kendi QTSP |
|---|---|---|
| Sure | 1-3 ay | 2-3 yil |
| Maliyet | €10K-€50K + €0.50-€5/QES | €500K-€1M+ initial |
| Yillik | Per-signature maliyet | €200K-€500K+ |
| Kontrol | Sinirli | Tam |
| Risk | Dusuk | Yuksek |
| Breakeven | - | 1,000+ QES/ay |

**Karar: Faz 3'te QTSP partnerligi.** Volume hakliyorsa (1,000+ QES/ay) Faz 5'te kendi QTSP degerlendirmesi.

### 33.2 Potansiyel QTSP Partnerleri

- **Swisscom Trust Services** (Avusturya) — Genis partner ekosistemi, API
- **Namirial** (Italya) — Full API, white-label
- **InfoCert** (Italya) — Banka/finans odakli
- **SK ID Solutions** (Estonya) — Smart-ID/Mobile-ID, Baltik bolgesi
- **Evrotrust** (Bulgaristan) — Mobil QES, 58 ulke

### 33.3 Entegrasyon

- CSC API (Cloud Signature Consortium) standardi — ETSI TS 119 432
- Signing akisi: Auth Server (kullanici dogrulama) -> QTSP API (sertifika + imza) -> Signed document
- Document hash signing (dokuman QTSP'ye gonderilmez, sadece hash)

---

## 34. Rakip Analizi Ozeti

Hedefledigimiz sertifika portfolyosu hicbir mevcut provider'da tam olarak bulunmuyor:

| Ozellik | Biz | Auth0 | Firebase | Supabase | Descope | Hanko | WorkOS | Zitadel | Ory | SuperTokens |
|---------|-----|-------|----------|----------|---------|-------|--------|---------|-----|-------------|
| OpenID FAPI 2.0 | Hedef | FAPI 1 | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir |
| FIDO2 Certified | Hedef | Hayir | Hayir | Hayir | Evet | Evet | Hayir | Hayir | Hayir | Hayir |
| OpenID Certified | Hedef | Evet | Evet* | Hayir | Hayir | Hayir | Hayir | Hayir | Evet (Hydra) | Hayir |
| SOC 2 Type II | Hedef | Evet | Evet | Evet | Evet | Hayir | Evet | Evet | Hayir | Hayir |
| ISO 27001 | Hedef | Evet | Evet | Beklemede | Evet | Hayir | Hayir | Evet | Hayir | Hayir |
| PCI DSS v4.0.1 | Hedef | Evet | Evet | Hayir | Evet | Hayir | Hayir | Hayir | Hayir | Hayir |
| FedRAMP High | Hedef | Hayir | Evet* | Hayir | Evet | Hayir | Hayir | Hayir | Hayir | Hayir |
| HIPAA | Hedef | Evet | Evet | Evet | Evet | Hayir | Evet | Hayir | Hayir | Hayir |
| PSD2/PSD3 SCA | Hedef | Evet | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir |
| eIDAS / EUDI | Hedef | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir |
| Blocking Hooks | Hedef | Evet | Hayir | Kismi | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir |
| Device Attestation | Hedef | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir |
| Transaction Approval | Hedef | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir |
| Self-hosted | Evet | Hayir | Hayir | Evet | Hayir | Evet | Hayir | Evet | Evet | Evet |
| AI Agent Auth | Hedef | Evet | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir |
| PIV/CAC Auth | Hedef | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir | Hayir |

*\* = inherited from Google Cloud*
*Not: Stytch Kasim 2025'te Twilio tarafindan satin alindi — bagimsiz fiyatlandirmasi degisebilir*
*Not: Descope su an en guclu compliance portfolyosune sahip yeni girisimci (SOC 2 + ISO + FIDO + FedRAMP High)*

---

## 35. Email Altyapisi & Guvenligi

### 31.1 Anti-Spoofing (PCI DSS v4.0.1 zorunlu)

- **SPF**: DNS'te hangi sunucularin email gonderebilecegi tanimlanir
- **DKIM**: Her email kriptografik olarak imzalanir
- **DMARC**: `p=reject` ile sahte emailler reddedilir

### 31.2 Email Gonderim

- Pluggable provider: AWS SES, SendGrid, Postmark, SMTP
- Tenant bazinda email konfigurasyonu (kendi SMTP'sini kullanabilir)
- Bounce handling: Hard bounce -> email'i unverified yap. Soft bounce -> retry
- Complaint handling: Spam sikayet -> log + tenant'a bildir
- Rate limit: Kullanici basina saatte max email sayisi
- Template rendering'de XSS korumasi (sandboxed, otomatik escape)
- Plaintext fallback her email icin zorunlu

---

## 36. SAML 2.0 Destegi

### 32.1 SP (Service Provider) Modu

Auth server SAML SP olarak calisir — harici SAML IdP'lerden (ADFS, Okta, Azure AD) identity kabul eder.

- SAML Assertion parsing ve dogrulama
- XML Signature Verification (XML DSig)
- Assertion encryption destegi (AES-256)
- NameID format destegi: emailAddress, persistent, transient
- Single Logout (SLO) destegi
- Metadata endpoint: `/.well-known/saml-metadata.xml`

### 32.2 IdP (Identity Provider) Modu

Auth server kendisi SAML IdP olarak calisir — eski sistemlere SAML ile entegrasyon saglar.

- SAML Response/Assertion uretimi
- SP metadata import
- Attribute mapping (SAML attributes -> user claims)
- Per-tenant IdP konfigurasyonu

### 36.3 PIV/CAC Authentication (FedRAMP High Zorunlu)

- NIST SP 800-53 Rev. 5 IA-2(12): "Accept and electronically verify Personal Identity Verification-compliant credentials"
- FedRAMP High'da Low/Moderate/High tum seviyeler icin zorunlu
- Uygulama yolu: Federated identity — SAML/OIDC ile PIV/CAC destekleyen harici IdP uzerinden
- Auth server PIV-aware SAML SP olarak calisir, IdP (ornek: ICAM, Login.gov) PIV/CAC dogrulamasini yapar
- Certificate-based auth: X.509 client sertifikasi ile mTLS destegi
- PIV credential verification: OCSP/CRL ile sertifika gecerlilik kontrolu

### 36.4 Guvenlik

- XXE korumasi: External entity resolution KAPALI
- DTD processing KAPALI
- XML bomb (billion laughs) korumasi: max entity depth + max document size

---

## 37. HTTP & Transport Guvenligi

### 33.1 Security Headers

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

### 33.2 CORS

- Tenant bazinda origin whitelist
- Wildcard (`*`) origin YASAK
- Credentials mode'da sadece explicit origin'ler
- Preflight cache: max 1 saat

### 33.3 IP Allowlisting

- Admin API'leri icin IP allowlist (tenant yapilandirilabilir)
- Management API icin ayri allowlist
- IPv4 ve IPv6 CIDR destegi

### 33.4 Request Validation

- Max request body size: 1MB
- Content-Type validation: Sadece `application/json`
- JSON depth limit: Max 10 seviye
- Input sanitization: Tum string input'lar trim + length check

---

## 38. Token Introspection & Revocation

### 34.1 Token Introspection (RFC 7662)

```
POST /oauth/introspect
Authorization: Basic <client_credentials>

token=<opaque_token>&token_type_hint=refresh_token
```

Response:
```json
{
  "active": true,
  "sub": "usr_xyz",
  "client_id": "app_abc",
  "scope": "openid profile",
  "exp": 1711900000,
  "tenant_id": "tenant_abc"
}
```

- Opaque refresh token'lar icin zorunlu
- Client authentication zorunlu
- Rate limited

### 34.2 Token Revocation (RFC 7009)

```
POST /oauth/revoke
Authorization: Basic <client_credentials>

token=<token>&token_type_hint=refresh_token
```

- Refresh token revoke -> iliskili tum access token'lar da gecersiz
- Access token revoke -> blocklist'e eklenir (JWT icin)
- Revocation her zaman 200 doner (bilgi sizintisi onleme)

---

## 39. Data Residency & Sovereignty

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

## 40. Altyapi Guvenligi & Operasyonel Prosedurler

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

## 41. i18n & Accessibility

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

## 42. Fonksiyonel Faz Plani

> **Oncelik: Self-hosted first.** Tum fazlarda birincil deployment self-hosted (Docker/Helm).
> Dashboard (Next.js) her fazda self-hosted ile birlikte gelir.
> SaaS katmani (billing, onboarding, managed hosting) Faz 4+'te eklenir.

### Faz 0: Core Auth (Ay 1-4)

> Hedef: Piyasadaki servislerin %95'inden daha guvenli bir temel. `docker compose up` ile ayaga kalkar.
> 24 deliverable, 14-16 hafta. Library kullanimi: `argon2`, `jose`, `ioredis`, vb.
> Solo developer icin gercekci timeline. 12 haftada MVP, 16 haftada production-quality.

**Deployment:**
- Docker Compose: server + dashboard + postgres + redis
- Setup wizard: Ilk acilista admin hesap + temel konfigurasyon
- `http://localhost:3000` (API) + `http://localhost:3001` (Dashboard)

**Core:**
1. NestJS monorepo (server + dashboard + client SDK + server SDK + shared)
2. PostgreSQL + Redis altyapisi + CI/CD pipeline
3. Database schema + migration sistemi
4. Tenant yonetimi (temel CRUD, API key uretimi: `pk_test_`, `sk_test_`)
5. Email + Password (Argon2id + pepper + salt + HIBP + constant-time)
6. Email verification (OTP veya magic link)
7. Password reset (256-bit token, 15dk)
8. JWT access token (PS256/ES256, 30dk) + JWKS endpoint
9. Opaque refresh token (rotation + family-based revocation, 30sn grace period)
10. Session yonetimi (idle/absolute timeout, aktif session listesi)
11. Audit log (structured JSON, SHA-256 hash chain on ciphertext, PII encryption)
12. Rate limiting (Redis sliding window, per-IP + per-endpoint)
13. Security headers (HSTS, CSP, CORS, X-Frame-Options)
14. Request validation (body size, content-type, JSON depth)
15. Email altyapisi (pluggable provider, SPF/DKIM/DMARC rehberi)
16. Health check + readiness endpoints
17. Test suite (unit + integration + E2E temel)

**SDK'lar:**
18. Client SDK: signUp, signIn, signOut, getSession, getUser, onAuthStateChange, auto-refresh
19. Server SDK: verifyToken, admin.createUser, updateUser, deleteUser, listUsers

**Dashboard (Next.js):**
20. Overview: aktif kullanici, login trendi
21. Users: liste, detay, ban, password reset
22. Authentication: provider toggle, password policy, session policy
23. Settings: email provider, CORS, redirect URLs
24. Audit Logs: real-time stream, filtre

**Neden %95'inden guvenli:**
- Argon2id + pepper + salt (cogu sistem bcrypt bile kullanmiyor)
- HIBP kontrolu (neredeyse kimse yapmiyor)
- Token rotation + stolen token detection (family-based revocation)
- Tamper-evident audit log (hash chain)
- Constant-time comparison (timing attack korumasi)
- Security headers (cogu startup eksik)

**Sertifika:** NIST AAL1, GDPR temel

---

### Faz 1: MFA + Social + Hooks (Ay 5-7)

> Hedef: Firebase/Supabase seviyesi + blocking hooks avantaji. Self-hosted + Helm chart.

**Core:**
1. TOTP MFA (QR enrollment, AES-256-GCM secret, backup codes)
2. Social login: Google, Apple, GitHub, Microsoft (Auth Code + PKCE)
3. Account linking (verified email ile otomatik)
4. Magic link (256-bit token, 15dk)
5. Blocking hooks (before.user.create, before.login + after variants)
6. Webhook sistemi (HMAC imza, retry, temel)
7. Session: device metadata binding, concurrent limit, remote revocation

**SDK'lar:**
8. Client SDK: signInWithOAuth, signInWithCredential, mfa.enroll/verify, recovery codes
9. Server SDK: hooks.before(), on(), admin.setCustomClaims, revokeAllSessions

**Dashboard:**
10. Hooks & Webhooks: endpoint, test, loglar, failure mode
11. Authentication: social provider konfig UI (Client ID/Secret girisi)
12. Users: MFA durumu, login gecmisi

**Deployment:**
13. Helm chart (Kubernetes)
14. Production Docker image'lar (multi-stage build, non-root)

**Sertifika:** NIST AAL2, OpenID Basic OP basvurusu baslar

---

### Faz 2: Passkeys + Enterprise (Ay 8-10)

> Hedef: Clerk/WorkOS seviyesi. FIDO2 + OpenID sertifika basvurulari.

**Core:**
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

**SDK'lar:**
11. NestJS SDK (@RequireAuth, @CurrentUser, hook handler interface)
12. Edge SDK (<50KB, JWKS cache, JWT verify, Cloudflare Workers + Vercel Edge)

**Dashboard:**
13. Organizations: org listesi, member yonetimi, davet
14. Security: risk engine konfig, IP whitelist, geo-blocking, bot detection
15. Analytics: auth method dagilim, MFA adoption, risk score dagilimi

**Sertifika:** FIDO2 basvuru, OpenID Basic OP, SOC 2 gozlem baslar

---

### Faz 3: Financial-Grade (Ay 11-16)

> Hedef: Auth0 seviyesi + device attestation + PSD2 SCA. SAML tek basina 2-4 ay surebilir.

**Core:**
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

**Dashboard:**
13. Organizations: SSO konfig (SAML metadata upload, OIDC discovery), SCIM
14. Webhook: DLQ, replay, fan-out
15. Security: device attestation sonuclari
16. Compliance: GDPR DSAR islem paneli

**Sertifika:** FIDO2 alinir, FAPI basvuru, SOC 2 gozlem devam

---

### Faz 4: Scale + Compliance + SaaS Baslangic (Ay 17-22)

> Hedef: SOC 2 raporu alma. Multi-region. SaaS katmani baslar.

**Core:**
1. Multi-region deployment (data residency: EU, US, APAC, TR)
2. Custom domain per tenant (Let's Encrypt/ACME)
3. White-label (login sayfalari, email template'ler, branding)
4. Advanced risk engine (3rd party connectors, behavioral signals)
5. Admin impersonation (RFC 8693 token exchange, audit trail)
6. Advanced webhook (DLQ, replay, fan-out, delivery logs)

**Operasyonel (sertifika icin):**
7. Backup & DR (PITR, encrypted backup, 6 aylik DR test)
8. Vulnerability management (dependency scan, DAST, pentest)
9. Incident response plan (documented, yillik exercise)
10. Change management proseduru

**SaaS katmani (baslangiç):**
11. Stripe billing entegrasyonu (subscription + usage-based MAU)
12. SaaS onboarding akisi (signup -> proje olustur -> quickstart)
13. Managed hosting altyapisi
14. Landing page / marketing site

**Diger:**
15. i18n (en, tr + framework)
16. Migration araclari (Auth0, Firebase, Supabase, Clerk import)

**Sertifika:** SOC 2 Type II ALINIR, ISO 27001 baslar, PCI DSS gap analysis

---

### Faz 5: Global Compliance + Full SaaS (Ay 23-36)

> Hedef: Tam sertifika portfolyosu + tam SaaS platform. Piyasada esdegeri olmayan platform.

**Sertifikalar:**
1. ISO 27001 sertifikasi
2. PCI DSS v4.0.1 sertifikasi
3. HIPAA BAA
4. CSA STAR Level 2
5. FedRAMP High basvurusu
6. eIDAS LoA High (QTSP entegrasyonu)

**Yeni ozellikler:**
7. AI Agent / MCP auth (agent entity, OAuth 2.1, RFC 8693 token exchange)
8. EUDI Wallet (OpenID4VP, selective disclosure)
9. Continuous auth (behavioral signals -> risk engine)
10. KYC entegrasyon hook'lari
11. Full i18n (10+ dil, RTL)
12. WCAG 2.1 AA

**SaaS olgunlastirma:**
13. Free/Pro/Business/Enterprise tier'lar tam islevsel
14. Self-service SSO provisioning
15. Usage dashboard + billing alertleri
16. Developer documentation portal
17. Interactive API playground

**Sertifika:** ISO 27001, PCI DSS, HIPAA, CSA STAR, FedRAMP suruyor, FAPI 2.0, eIDAS

---

### Faz Ozet

| Faz | Sure | Deployment | Piyasa Esdegeri | Sertifika |
|-----|------|------------|-----------------|-----------|
| **0** | Ay 1-4 | Docker Compose | %95'inden guvenli | NIST AAL1, GDPR |
| **1** | Ay 5-7 | + Helm chart | Supabase/Firebase + hooks | NIST AAL2, OpenID basvuru |
| **2** | Ay 8-10 | Self-hosted production-ready | Clerk/WorkOS + FIDO2 | FIDO2 + OpenID, SOC 2 gozlem |
| **3** | Ay 11-16 | Financial-grade self-hosted | Auth0 + PSD2 SCA | FIDO2, FAPI basvuru |
| **4** | Ay 17-22 | + SaaS katmani baslar | Descope seviyesi | SOC 2 alinir, ISO + PCI baslar |
| **5** | Ay 23-36 | Full SaaS + self-hosted | Piyasada esdegeri YOK | Tam portfolyo |

---

## 43. SaaS Platform & Business Model

> **Not:** SaaS katmani Faz 4'te baslar. Self-hosted birincil deployment.
> Ancak mimari Day 1'den multi-tenant ve SaaS-ready tasarlanir.
> Dashboard (Next.js) her iki modda da ayni — SaaS'a ozel sadece billing + onboarding eklenir.

### 39.1 Deployment Modelleri

| Model | Faz | Aciklama | Hedef Kitle |
|-------|-----|----------|-------------|
| **Self-Hosted** | Faz 0+ | Docker/Helm ile kendi sunucusunda | Herkes, regulated industries |
| **SaaS (Managed)** | Faz 4+ | Biz host ediyoruz, dashboard'dan proje olustur | Startup, SMB, mid-market |
| **Private Cloud** | Faz 5+ | Dedicated instance, biz yonetiyoruz | Bankalar, fintech, devlet |

### 39.2 Fiyatlandirma

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

### 39.3 Proje & API Key Yapisi

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

### 39.4 Dashboard Rolleri

| Rol | Billing | Takim | Prod Config | Dev Config | Kullanici Verisi | Log |
|-----|---------|-------|-------------|------------|------------------|-----|
| Owner | Tam | Tam | Tam | Tam | Tam | Tam |
| Admin | Goruntule | Ekle/Cikar | Tam | Tam | Tam | Tam |
| Developer | - | - | Salt okunur | Tam | Goruntule | Goruntule |
| Viewer | - | - | - | - | Goruntule | Goruntule |

Dashboard'a giris: Google/GitHub SSO veya email+MFA. Enterprise: Kendi SAML/OIDC IdP'si ile.

### 39.5 Dashboard Sayfalari

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
- Her provider icin konfigurasyon (Client ID, Secret, scope)
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

### 39.6 Onboarding Akisi

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

### 39.7 Migration Araclari

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
