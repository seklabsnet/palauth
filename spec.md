# PalAuth - Technical Specification

> Self-hosted, certification-ready authentication & authorization platform.
> Go backend, multi-language SDK'lar, financial-grade security.
> Proje adi: **PalAuth**

### Dokumanlar

| Dosya | Icerik |
|-------|--------|
| **spec.md** (bu dosya) | Core Go server fonksiyonalitesi, altyapi, faz plani, test stratejisi, dashboard |
| [spec-compliance.md](spec-compliance.md) | Sertifikasyon, regulasyon, uyum (NIST, SOC 2, ISO, PCI DSS, FIDO2, FAPI, GDPR, PSD2, DORA, FIPS, ETSI, QES, rakip analizi) |
| [spec-sdk.md](spec-sdk.md) | SDK tasarimi (TypeScript client/server/edge/nestjs, Go, KMP mobile) |
| [spec-saas.md](spec-saas.md) | SaaS platform (ileride — Faz 4+) |

---

## 1. Vizyon & Hedefler

### 1.1 Ne Yapacagiz?

Firebase Auth, Supabase Auth, Auth0 gibi calisacak ama self-hosted, tum sertifikalara sahip, finansal islemleri destekleyen bir authentication platformu.

### 1.2 Temel Ilkeler

1. **Security-first**: Tum sertifikalari alabilecek seviyede guvenlik → detay: [spec-compliance.md](spec-compliance.md)
2. **Blocking pipeline**: Event-based degil, backend "tamam" demeden islem tamamlanmaz
3. **Entegrasyon kolayligi**: 3 satirda entegrasyon, developer-friendly SDK → detay: [spec-sdk.md](spec-sdk.md)
4. **Project izolasyonu**: Tek instance uzerinde birden fazla izole project destegi (project_id ile scope'lama)
5. **Financial-grade**: Para transferi, transaction approval, document signing destegi

### 1.3 Sertifika & Uyum

> Tam sertifika portfolyosu, maliyet tablosu, regulasyon detaylari: [spec-compliance.md](spec-compliance.md)


---

## 2. Authentication Yontemleri

### 2.1 Email + Password

- **Minimum 15 karakter** (tek faktorlu auth icin — NIST 800-63B-4 Sec 3.1.1.2, SHALL). MFA aktif ise minimum 8 karakter yeterli
- Max 64 karakter ust limit, truncate yasak (NIST 800-63B-4)
- Composition rules (numerik + alfa zorunlulugu) UYGULANMAZ (NIST 800-63B-4 SHALL NOT). PCI DSS v4.0.1 Req 8.3.6 bunu zorunlu kiliyor — bu catisma PCI DSS v4.0 **Customized Approach** veya **Compensating Controls Worksheet** ile dokumante edilir (her ikisi de **QSA validasyonu** gerektirir, SAQ ile kullanilamaz). Uygulanacak tam NIST 800-63B kontrol seti: compromised password DB kontrolu (HIBP), yaygin sifre bloklama, zorunlu rotasyon yok, salted hash (Argon2id). 15+ karakter uzunlugu + bu kontroller composition kuralini gereksiz kilar. Customized Approach icin ek gereksinimler: targeted risk analysis, kontrol matrisi, yonetici onayi, surekli izleme
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
| Normal kullanici girisi | Project tarafindan yapilandirilabilir | - |

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
- Omur (genel mod): 15-60dk (project yapilandirilabilir)
- Omur (FAPI 2.0 modu): Kisa omur ONERILIR ama normatif zorunluluk YOK. FAPI 2.0 Sec 6.1 non-normative: "consider using short-lived access tokens." **Varsayilan: 5dk.** Project override edebilir
- Claims: `sub`, `iss`, `aud`, `exp`, `iat`, `jti`, `kid`, `acr`, `amr`, `auth_time`, `project_id`, custom claims
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
| `before.token.issue` | Token uretilmeden once | Custom claims ekleme, project kontrolu |
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
  "project": {
    "id": "project_abc",
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
- Project'lar esik degerlerini yapilandirabilir

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

### 13.4 Service Account Credential Yonetimi (PCI DSS v4.0.1 §8.6.1–8.6.3)

> **31 Mart 2025 itibariyle zorunlu.** PCI DSS'in ilk kez non-human identity credential yonetimini acikca hedef alan gereksinimleri.

**8.6.1 — Interaktif erisimli service account'lar:**
- Her service/system account **benzersiz** tanimlanir (paylasimli hesap YASAK)
- Interaktif login yetenegi olan hesaplar icin: zaman sinirli erisim, yonetim onayi, tum aksiyonlarin bireysel kullaniciya atfedilmesi
- Sadece interaktif login *yapabilen* hesaplara uygulanir

**8.6.2 — Hard-coded credential yasagi:**
- Script, config dosyasi veya kaynak kodda hard-coded sifre/secret YASAK
- Credential'lar secrets vault'ta (HashiCorp Vault, AWS Secrets Manager, vb.) saklanir, runtime'da inject edilir
- Alternatif: sertifika-bazli auth (mTLS / `private_key_jwt`) ile static secret ihtiyacini ortadan kaldir

**8.6.3 — Credential rotation (en genis kapsam):**
- **Tum** application ve system account credential'lari periyodik olarak rotate edilir — interaktif olsun veya olmasin
- Rotation frekansi **Targeted Risk Analysis** (Req 12.3.1) ile belirlenir
- Supheli compromise durumunda **aninda** rotation
- Dual-credential overlap window: yeni credential aktif, eski credential grace period icinde gecerli (zero-downtime rotation)
- Auth server credential lifecycle event'lerini tamamen loglar (olusturma, rotation, iptal)

**Uygulama:**
- Credential rotation API: `POST /admin/service-accounts/{id}/rotate` — yeni credential uretir, eski icin yapilandirilabilir grace period baslatir
- Credential TTL: service account olusturulurken max omur belirlenir
- TRA export: credential lifecycle verileri Targeted Risk Analysis dokumantasyonunu desteklemek icin export edilebilir
- Dashboard'da service account credential durumu: son rotation, sonraki planlanan rotation, risk analizi baglantisi

---

## 14. Admin Impersonation

### 14.1 Mekanizma

- RFC 8693 Token Exchange ile impersonation token uretilir
- Token'da hem `actor` (admin) hem `subject` (hedef kullanici) claim'leri bulunur
- Tum aksiyonlar audit log'da `impersonated: true` flag'i ile isaretlenir

### 14.2 Kurallar

- Sadece belirli izne sahip admin'ler impersonate edebilir
- Max sure: yapilandirilabilir (varsayilan 1 saat)
- Impersonate edilen kullaniciya bildirim (opsiyonel, project yapilandirilabilir)
- Impersonation session'inda hassas islemler (sifre degistirme, MFA degisikligi) yapilamaz

---

## 15. Project Izolasyonu

> Go server single-tenant, multi-project. Bir kullanici (self-hosted) veya SaaS platformu birden fazla project olusturabilir. Her project tamamen izole.
> project_id tum tablolarda column olarak bulunur. Her sorgu project_id ile scope'lanir.
> Multi-tenancy Go server'da YOK — SaaS'ta orchestration layer (ayri repo) bunu yonetir.

### 15.1 Project = Izolasyon Birimi

Her project icin:
- Ayri user pool (project A'nin kullanicilari project B'yi goremez)
- Ayri auth yontemi konfigurasyonu (project A sadece passkey, project B email+password)
- Ayri API key'ler (`pk_live_xxx` / `sk_live_xxx` — project'e bagli)
- Ayri SSO baglantilari
- Ayri rate limit'ler ve kotalar
- Ayri audit log'lar
- Ayri webhook endpoint'leri
- Ayri branding (logo, renkler, email template'leri)

### 15.2 API Key -> Project Mapping

```
Client request:
  POST /auth/login
  Header: X-API-Key: pk_live_abc123

Go server:
  1. pk_live_abc123 -> projects tablosundan project_id = 'prj_abc' bulur
  2. Tum sorgular WHERE project_id = 'prj_abc' ile scope'lanir
  3. Farkli project'lerin verilerine erisim IMKANSIZ
```

### 15.3 Self-Hosted vs SaaS Kullanimi

| Senaryo | Nasil |
|---------|-------|
| Self-hosted (tek musteri) | 1-N project olusturur (web app, mobile app, admin panel) |
| SaaS Free tier | Shared PalAuth instance, her musteri = 1 project |
| SaaS Business tier | Dedicated PalAuth instance, musteri kendi project'lerini yonetir |
| SaaS Enterprise | Dedicated instance + dedicated DB, tam izolasyon |

### 15.4 Custom Domain

- Project basina ozel domain: `auth.myapp.com`
- Otomatik TLS sertifikasi (Let's Encrypt / ACME)
- Wildcard sertifika destegi

### 15.5 White-Label

- Login/register sayfalari project branding'i ile
- Email template'leri project'a ozel
- SMS icerikleri project'a ozel
- Hata mesajlari project diline gore

---

## 16. Audit Logging

### 16.1 Loglanan Olaylar

> Bu liste tum fazlardaki event'leri kapsar. Her faz kendi event'lerini ekler.

**Authentication (Faz 0):**
- `auth.signup`, `auth.login.success`, `auth.login.failure`
- `auth.logout`
- `auth.password.change`, `auth.password.reset.request`, `auth.password.reset.complete`
- `auth.email.verify`

**MFA (Faz 1):**
- `mfa.enroll`, `mfa.challenge`, `mfa.verify.success`, `mfa.verify.failure`
- `mfa.remove`, `mfa.recovery.used`

**Social (Faz 1):**
- `auth.social.login`, `social.link`, `social.unlink`

**Magic Link (Faz 1):**
- `auth.magic_link.request`, `auth.magic_link.verify`

**Hooks & Webhooks (Faz 1):**
- `hook.call.success`, `hook.call.failure`
- `webhook.delivery.success`, `webhook.delivery.failure`

**Session (Faz 0+):**
- `session.create`, `session.refresh`, `session.revoke`
- `session.anomaly` (Faz 2 — risk engine tetikler)

**Token (Faz 0):**
- `token.issue`, `token.refresh`, `token.revoke`

**WebAuthn (Faz 2):**
- `webauthn.register`, `webauthn.login`, `webauthn.remove`, `webauthn.clone_detected`

**Step-Up (Faz 2):**
- `auth.step_up.success`, `auth.step_up.failure`

**Risk (Faz 2):**
- `risk.evaluate`, `risk.block`
- `bot.pow.challenge`, `bot.stuffing.detected`, `bot.ip.blocked`

**Organizations (Faz 2):**
- `org.create`, `org.update`, `org.delete`
- `org.member.add`, `org.member.remove`, `org.member.role_change`
- `org.invitation.send`, `org.invitation.accept`, `org.domain.verify`

**OIDC (Faz 2):**
- `oidc.authorize`, `oidc.token.issue`

**SMS OTP (Faz 2):**
- `sms.otp.send`

**Admin (Faz 0+):**
- `admin.user.create`, `admin.user.update`, `admin.user.delete`
- `admin.user.deactivate_inactive`
- `admin.impersonate.start`, `admin.impersonate.end` (Faz 4)
- `admin.config.change`
- `admin.key.rotate`

**Device (Faz 3):**
- `device.attest.android`, `device.attest.ios`, `device.bind`, `device.revoke`, `device.clone_detected`

**Transaction (Faz 3):**
- `transaction.create`, `transaction.approve`, `transaction.deny`, `transaction.expire`

**SAML/SSO/SCIM (Faz 3):**
- `saml.login`, `saml.logout`, `sso.connect`
- `scim.user.create`, `scim.user.update`, `scim.user.delete`

**Credentials (Faz 3):**
- `apikey.create`, `apikey.revoke`
- `serviceaccount.create`, `serviceaccount.rotate`, `serviceaccount.revoke`
- `pat.create`, `pat.revoke`
- `m2m.token.issue`
- `dpop.bind`, `dpop.verify.failure`
- `par.request`

**Compliance (Faz 3):**
- `gdpr.export`, `gdpr.erasure`, `gdpr.consent.grant`, `gdpr.consent.revoke`
- `breach.detected`, `breach.forced_reset`
- `retention.purge`

**Recovery (Faz 4):**
- `recovery.contact.add`, `recovery.contact.remove`
- `recovery.initiate`, `recovery.approve`, `recovery.complete`

**Domain/Migration (Faz 4):**
- `domain.add`, `domain.verify`, `domain.tls.provision`
- `migration.start`, `migration.complete`

**Agent/EUDI/KYC (Faz 5):**
- `agent.create`, `agent.revoke`, `agent.delegation.grant`, `agent.delegation.revoke`
- `agent.token.issue`, `agent.token.exchange`
- `eudi.verify.begin`, `eudi.verify.complete`
- `kyc.initiate`, `kyc.complete`, `kyc.failed`

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
  "project_id": "project_abc",
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
- Project bazinda yapilandirilabilir retention suresi

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
| Per-project | Project basina | Token bucket |

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
- Ulke bazli beyaz/kara liste (project yapilandirilabilir)
- Impossible travel detection: Haversine formula ile mesafe, hiz hesabi

---

## 19. Webhook & Event Streaming

### 19.1 Webhook Sistemi

- Project'lar endpoint URL'leri register eder
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

- Yapilandirilabilir retention suresi (project bazinda)
- Otomatik purging (sifreleme key'i silme ile)
- Retention suresi dolan veriler otomatik temizlenir

### 24.3 Compliance Raporlari

- Login basari/basarisizlik istatistikleri
- MFA adoption oranlari
- Password age dagilimi
- Session anomali raporlari
- Audit log export (compliance-friendly format)

---

## 25-26: SDK Tasarimi

> Tum SDK tasarimi, kod ornekleri, platform detaylari: [spec-sdk.md](spec-sdk.md)
> Client SDK, Server SDK, Edge SDK, NestJS SDK, Go SDK, KMP Mobile SDK

---

## 27. Veritabani Semasi (Ozet)

### Core Tablolar

- `projects` — Project konfigurasyonu (izolasyon birimi, her project ayri user pool)
- `users` — Kullanici profilleri (project_id ile scope'lanir)
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

- PII alanlari (email, telefon, isim): AES-256-GCM, per-project DEK
- Credential alanlari (TOTP secret, recovery codes): AES-256-GCM, per-user DEK
- Audit log PII alanlari: AES-256-GCM, per-user DEK (cryptographic erasure icin)

---

## 28. Altyapi Gereksinimleri

### 28.1 Monorepo Yapisi

```
authserver/
  cmd/
    server/              → Go main binary entry point
  internal/              → Go core logic (disariya export edilmez)
    auth/                → Signup, login, password reset, email verify
    token/               → JWT issuance, refresh rotation, DPoP, JWKS
    session/             → Session lifecycle, device binding, timeout
    mfa/                 → TOTP, WebAuthn enrollment/verify, backup codes
    oauth/               → OIDC Provider, authorization code, PKCE, PAR
    social/              → Social login providers (Google, Apple, GitHub...)
    saml/                → SAML SP + IdP
    hook/                → Blocking pipeline, HMAC signing, timeout handling
    webhook/             → Delivery, retry, DLQ, replay
    risk/                → Risk engine, scoring, signals
    device/              → Attestation (Play Integrity, App Attest), binding
    transaction/         → PSD2 SCA, dynamic linking, WYSIWYS
    project/              → Project CRUD, config, API key yonetimi
    org/                 → Organizations, members, roles, invitations
    audit/               → Tamper-evident log, hash chain, cryptographic erasure
    crypto/              → Envelope encryption, key rotation, FIPS mode
    ratelimit/           → Redis sliding window, per-layer limiting
    user/                → User CRUD, ban, custom claims
    apikey/              → API key, M2M, PAT management
    scim/                → SCIM 2.0 endpoint
    recovery/            → Recovery codes, trusted contacts, admin-assisted
    bot/                 → Proof-of-Work challenge
    email/               → Pluggable provider, templates, bounce handling
    agent/               → AI agent auth, MCP compat, token exchange
    eudi/                → OpenID4VP verifier, selective disclosure
    breach/              → HIBP check, credential monitoring
    compliance/          → GDPR DSAR, data retention, consent
  pkg/                   → Disariya export edilebilir Go paketleri
    sdk/                 → Go Server SDK
  api/
    openapi.yaml         → OpenAPI spec (source of truth — tum SDK'lar buradan turetilir)
  sdk/
    typescript/
      client/            → @palauth/client (Next.js, React, Vue, browser)
      server/            → @palauth/server (NestJS, Express, Fastify backend)
      edge/              → @palauth/edge (<50KB, Cloudflare Workers, Vercel Edge)
      nestjs/            → @palauth/nestjs (decorator-based wrapper)
    go/                  → palauth-go (Go backend SDK)
    mobile/              → palauth-mobile (Kotlin Multiplatform — iOS + Android)
    python/              → palauth-python (ileride)
    java/                → palauth-java (ileride)
  dashboard/             → Next.js admin panel
  docker/
    docker-compose.yml   → Dev ortami (server + dashboard + postgres + redis)
    Dockerfile.server    → Production server image (multi-stage, scratch base, ~15MB)
    Dockerfile.dashboard → Production dashboard image
  helm/
    authserver/          → Kubernetes Helm chart
  migrations/            → SQL migration dosyalari (golang-migrate)
  docs/
    quickstart/          → Framework-bazli quickstart rehberleri
    api-reference/       → OpenAPI spec'ten otomatik uretim (Redoc/Scalar)
  tests/
    e2e/                 → Playwright E2E testleri
    conformance/         → OpenID/FIDO2/FAPI conformance runner
    load/                → k6 load test senaryolari
    chaos/               → Toxiproxy chaos test senaryolari
```

**Go Tech Stack:**

| Katman | Arac | Neden |
|--------|------|-------|
| HTTP framework | Chi (veya stdlib Go 1.22+) | Minimal, idiomatic, net/http uyumlu |
| Database | PostgreSQL 16+ (pgx driver) | Direct SQL, no ORM. sqlc ile type-safe query generation |
| Cache / Rate limit | Redis 7+ (go-redis) | Sliding window, session cache, token blacklist |
| JWT | go-jose/v4 | Full JOSE (JWE, JWS, JWT, JWK), RFC uyumlu |
| OIDC | zitadel/oidc (OpenID Certified) | OP + RP, production-tested |
| WebAuthn | go-webauthn (FIDO Conformant) | Passkey, MFA, attestation |
| SAML | crewjam/saml v0.5.1 | SP + IdP, CVE'ler fixli |
| Argon2id | alexedwards/argon2id | Secure defaults, PHC format wrapper |
| DPoP | AxisCommunications/go-dpop v1.1.2 | Proof generation + validation (vendor/fork) |
| SCIM | elimity-com/scim | CRUD + schema validation (pin commit) |
| Event system | Go channels (Faz 0), watermill v1.5.1 (Faz 2+) | In-memory → Kafka/Redis/NATS |
| Config | knadh/koanf v2.3.4 | Viper'dan %313 kucuk, modular |
| Logging | slog (stdlib) + samber/slog-multi | Go 1.24, structured, fan-out |
| Validation | go-playground/validator v10 | Struct tag-based, 19.8K stars |
| Migration | pressly/goose v3.27.0 | SQL + Go migrations |
| OpenAPI codegen | oapi-codegen v2.6.0 | Spec-first, Chi first-class |
| FIPS 140-3 | Go 1.24 native module | Sertifika A6650, cgo gerektirmez |
| Metrics | prometheus/client_golang v1.23.2 | /metrics endpoint |
| Rate limiting | go-chi/httprate + httprate-redis | Chi-native sliding window |
| CORS | rs/cors v1.11.1 | Router-agnostic, 2.8K stars |
| ID generation | google/uuid (UUIDv7) | RFC 9562, PG native uuid |
| TOTP (Faz 1) | pquerna/otp v1.5.0 | TOTP + HOTP |
| OAuth2 client (Faz 1) | golang.org/x/oauth2 v0.36.0 | Native PKCE destegi |
| IP Geolocation (Faz 2) | oschwald/geoip2-golang v2.1.0 | MaxMind GeoLite2 |
| ACME/TLS (Faz 4) | caddyserver/certmagic v0.25.2 | Auto HTTPS, distributed |
| Play Integrity (Faz 3) | google.golang.org/api/playintegrity/v1 | Resmi Google client |
| App Attest (Faz 3) | splitsecure/go-app-attest | En aktif, kodu audit et |

> Tam paket referansi: [packages.md](packages.md)

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

- **Dil**: Go 1.24+ (FIPS 140-3 native module icin minimum)
- **Framework**: Chi router (veya Go 1.22+ stdlib enhanced routing)
- **Veritabani**: PostgreSQL 16+ (pgx driver, sqlc ile type-safe queries)
- **Cache/Rate limit**: Redis 7+ (go-redis)
- **Event/Message**: Watermill (in-memory dev, Redis Streams prod)
- **KMS**: AWS KMS / GCP KMS / HashiCorp Vault (key management)
- **Binary**: Tek statik binary (~15MB), sifir runtime dependency

### 28.4 Self-Hosted Deployment

**Standalone binary (en basit):**
```bash
# Tek binary indir + calistir
curl -L https://github.com/authserver/releases/latest/authserver-linux-amd64 -o authserver
chmod +x authserver
./authserver serve --config config.yaml
# API:       localhost:3000
# Dashboard: localhost:3001 (ayri Next.js container veya embedded)
```

**Docker Compose (gelistirme + kucuk olcek):**
```bash
docker compose up -d
# authserver:        localhost:3000  (Go binary, ~15MB image)
# authserver-admin:  localhost:3001  (Next.js dashboard)
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
# Image: scratch base, ~15MB (NestJS: ~300MB)
# Memory: ~20MB idle (NestJS: ~120MB)
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
- Config file (YAML) via koanf
- Tum ayarlar dashboard veya API ile de degistirilebilir
- Ilk acilista setup wizard (admin hesap + temel konfigurasyon)
- FIPS mode: `--fips` flag veya `AUTHSERVER_FIPS=true` env var

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

## 29-34: Sertifikasyon & Regulasyon

> Bu bolumler [spec-compliance.md](spec-compliance.md) dosyasina tasinmistir:
> PSD3/PSR, DORA, FIPS 140-3, ETSI TS 119 461, QES stratejisi, rakip sertifika analizi, NIST 800-63B-4 AAL seviyeleri, GDPR, data residency, operasyonel prosedurler.

---
## 35. Email Altyapisi & Guvenligi

### 35.1 Anti-Spoofing (PCI DSS v4.0.1 zorunlu)

- **SPF**: DNS'te hangi sunucularin email gonderebilecegi tanimlanir
- **DKIM**: Her email kriptografik olarak imzalanir
- **DMARC**: `p=reject` ile sahte emailler reddedilir

### 35.2 Email Gonderim

- Pluggable provider: AWS SES, SendGrid, Postmark, SMTP
- Project bazinda email konfigurasyonu (kendi SMTP'sini kullanabilir)
- Bounce handling: Hard bounce -> email'i unverified yap. Soft bounce -> retry
- Complaint handling: Spam sikayet -> log + project'a bildir
- Rate limit: Kullanici basina saatte max email sayisi
- Template rendering'de XSS korumasi (sandboxed, otomatik escape)
- Plaintext fallback her email icin zorunlu

---

## 36. SAML 2.0 Destegi

### 36.1 SP (Service Provider) Modu

Auth server SAML SP olarak calisir — harici SAML IdP'lerden (ADFS, Okta, Azure AD) identity kabul eder.

- SAML Assertion parsing ve dogrulama
- XML Signature Verification (XML DSig)
- Assertion encryption destegi (AES-256)
- NameID format destegi: emailAddress, persistent, transient
- Single Logout (SLO) destegi
- Metadata endpoint: `/.well-known/saml-metadata.xml`

### 36.2 IdP (Identity Provider) Modu

Auth server kendisi SAML IdP olarak calisir — eski sistemlere SAML ile entegrasyon saglar.

- SAML Response/Assertion uretimi
- SP metadata import
- Attribute mapping (SAML attributes -> user claims)
- Per-project IdP konfigurasyonu

### 36.3 PIV/CAC Authentication (FedRAMP High Zorunlu)

- NIST SP 800-53 Rev. 5 IA-2(12): "Accept and electronically verify Personal Identity Verification-compliant credentials"
- FedRAMP High'da Low/Moderate/High tum seviyeler icin zorunlu
- Uygulama yolu: Federated identity — SAML/OIDC ile PIV/CAC destekleyen harici IdP uzerinden
- Auth server PIV-aware SAML SP olarak calisir, IdP (ornek: ICAM, Login.gov) PIV/CAC dogrulamasini yapar. **Not:** Login.gov su an FedRAMP Moderate — FedRAMP High sistemler icin FedRAMP High yetkili bir IdP veya kurum-owned PIV altyapisi gerekir
- Certificate-based auth: X.509 client sertifikasi ile mTLS destegi
- PIV credential verification: OCSP/CRL ile sertifika gecerlilik kontrolu

### 36.4 Guvenlik

- XXE korumasi: External entity resolution KAPALI
- DTD processing KAPALI
- XML bomb (billion laughs) korumasi: max entity depth + max document size

---

## 37. HTTP & Transport Guvenligi

### 37.1 Security Headers

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

### 37.2 CORS

- Project bazinda origin whitelist
- Wildcard (`*`) origin YASAK
- Credentials mode'da sadece explicit origin'ler
- Preflight cache: max 1 saat

### 37.3 IP Allowlisting

- Admin API'leri icin IP allowlist (project yapilandirilabilir)
- Management API icin ayri allowlist
- IPv4 ve IPv6 CIDR destegi

### 37.4 Request Validation

- Max request body size: 1MB
- Content-Type validation: Sadece `application/json`
- JSON depth limit: Max 10 seviye
- Input sanitization: Tum string input'lar trim + length check

---

## 38. Token Introspection & Revocation

### 38.1 Token Introspection (RFC 7662)

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
  "project_id": "project_abc"
}
```

- Opaque refresh token'lar icin zorunlu
- Client authentication zorunlu
- Rate limited

### 38.2 Token Revocation (RFC 7009)

```
POST /oauth/revoke
Authorization: Basic <client_credentials>

token=<token>&token_type_hint=refresh_token
```

- Refresh token revoke -> iliskili tum access token'lar da gecersiz
- Access token revoke -> blocklist'e eklenir (JWT icin)
- Revocation her zaman 200 doner (bilgi sizintisi onleme)

---

## 39-40: Compliance & Operasyonel

> Data residency, network segmentation, backup/DR, change management, incident response, vulnerability management: [spec-compliance.md](spec-compliance.md)

---
## 41. i18n & Accessibility

### 41.1 Internationalization

- Hata mesajlari: 10+ dil destegi (en, tr, de, fr, es, ar, zh, ja, ko, pt minimum)
- Email template'leri: Project + dil bazinda
- SMS icerikleri: Dil bazinda
- Login/register sayfalari: RTL (sagdan sola) destegi (Arapca, Ibranice)
- Tarih/saat formati: Locale-aware
- Telefon numarasi formati: E.164 + ulke kodu destegi

### 41.2 Accessibility (WCAG 2.1 AA)

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
> 24 deliverable, 14-16 hafta. Go kutuphaneleri: `golang.org/x/crypto/argon2`, `go-jose`, `go-redis`, `chi`, `sqlc`, `pgx`, `zitadel/oidc`, `go-webauthn` vb.
> Solo developer icin gercekci timeline. 12 haftada MVP, 16 haftada production-quality.

**Deployment:**
- Docker Compose: server (Go ~15MB image) + dashboard (Next.js) + postgres + redis
- Setup wizard: Ilk acilista admin hesap + temel konfigurasyon
- `http://localhost:3000` (API) + `http://localhost:3001` (Dashboard)

**Core (Go):**
1. Go monorepo (cmd/server + internal/* + sdk/* + dashboard + migrations)
2. PostgreSQL + Redis altyapisi + CI/CD pipeline
3. Database schema + migration sistemi (golang-migrate)
4. Project yonetimi (CRUD, config, API key uretimi: `pk_test_`/`sk_test_`/`pk_live_`/`sk_live_`)
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

**SDK'lar (TypeScript — OpenAPI spec'ten generate):**
18. Client SDK (@palauth/client): signUp, signIn, signOut, getSession, getUser, onAuthStateChange, auto-refresh (Next.js icin)
19. Server SDK (@palauth/server): verifyToken, admin.createUser, updateUser, deleteUser, listUsers (NestJS backend icin)
20. Go Server SDK (palauth-go): Ayni fonksiyonlar, Go native

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
11. NestJS SDK (@palauth/nestjs — @RequireAuth, @CurrentUser, hook handler interface)
12. Edge SDK (@palauth/edge — <50KB, JWKS cache, JWT verify, Cloudflare Workers + Vercel Edge)
13. KMP Mobile SDK (palauth-mobile — iOS + Android, Kotlin Multiplatform)

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
2. Custom domain per project (Let's Encrypt/ACME). SaaS'ta upgrade yapan musterinin project verisi shared instance'dan dedicated instance'a migrate edilir
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

## 43. Test Stratejisi

### 43.1 Yaklasim

**"Testing Pyramid + Security Layers"** modeli. TDD sadece unit test katmaninda — tum strateji degil, stratejinin %20'si. Auth server icin tek bir test yaklasimiyla yetinmek yetersiz: Trail of Bits (Eylul 2025) %96 code coverage olan bir projede mutation testing skorunun %34 oldugunu buldu — testlerin 2/3'u sahte guvenlik hissi veriyordu.

### 43.2 Test Piramidi (11 Katman + AI Security)

#### Katman 1: Unit Tests (TDD)

- **Arac:** Go `testing` stdlib + `testify` (assertions + mocking)
- **Mock generation:** `mockery` (interface'lerden otomatik mock uretir)
- **Yaklasim:** Test-first (Security Test-Driven Development — STDD)
- **Kapsam:** Core business logic — password policy, token claim uretimi, risk score hesaplama, rate limit counter, hash chain hesaplama, OTP uretimi/dogrulama
- **Kapsam DISI:** Kripto kutuphaneleri (argon2, go-jose), DB driver (pgx)
- **Hedef:** Guvenlik-kritik modullerde %90+ line coverage

```go
// Ornek: Timing attack korumasi testi
func TestConstantTimeComparison(t *testing.T) {
    hash, _ := passwordService.Hash("correct-password")
    times := make([]int64, 100)
    for i := 0; i < 100; i++ {
        start := time.Now()
        _ = passwordService.Verify(fmt.Sprintf("wrong-%d", i), hash)
        times[i] = time.Since(start).Nanoseconds()
    }
    stdDev := standardDeviation(times)
    assert.Less(t, stdDev, int64(1_000_000)) // < 1ms variance
}
```

#### Katman 2: Property-Based Tests

- **Arac:** `flyingmutant/rapid` (Go, Hypothesis-inspired, otomatik shrinking)
- **Yaklasim:** Invariant tanimlama — "HER input icin bu kural gecerli olmali"
- 10,000+ rastgele input uretir, insanin dusunemeyecegi edge case'leri bulur

**Auth icin invariantlar:**
- Her iki farkli password'un hash'i farkli olmali (salt uniqueness)
- Her JWT'nin `exp > iat` olmali
- Refresh token rotation sonrasi eski token HER ZAMAN gecersiz olmali
- Risk score her zaman 0.0-1.0 arasinda olmali
- Canonical JSON serialization her zaman deterministic olmali (audit log hash chain)
- Token family revocation sonrasi tum descendants gecersiz olmali

```go
// Ornek: Salt uniqueness invariant
func TestSaltUniqueness(t *testing.T) {
    rapid.Check(t, func(t *rapid.T) {
        pw := rapid.String().Draw(t, "password")
        hash1, _ := passwordService.Hash(pw)
        hash2, _ := passwordService.Hash(pw) // ayni password
        assert.NotEqual(t, hash1, hash2) // farkli salt = farkli hash
    })
}
```

#### Katman 3: AI Security Review

- **Arac:** Claude Code Security Review (GitHub Action — `anthropics/claude-code-security-review`, MIT lisans)
- **Ne yapar:** Her PR'daki diff'i analiz eder, pattern matching degil **baglam anlayarak** guvenlik acigi arar
- **Tespit ettikleri:**
  - Injection saldirilari (SQL, command, NoSQL, XXE, XPath)
  - Auth/authorization hatalari (privilege escalation, IDOR, bypass logic)
  - Hardcoded secret'lar, hassas loglama, PII ihlalleri
  - Zayif kriptografi, kotu key management
  - Business logic hatalari (race condition, TOCTOU)
  - Supply chain riskleri (vulnerable dependency, typosquatting)
- **Cikti:** PR'da dogrudan kod satirina yorum, severity rating, remediation onerisi
- **Ek:** Development sirasinda `claude /security-review` CLI komutu ile lokal tarama

```yaml
# .github/workflows/security-review.yml
name: Security Review
on: [pull_request]
jobs:
  security-review:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-security-review@main
        with:
          claude_api_key: ${{ secrets.CLAUDE_API_KEY }}
```

#### Katman 4: Integration Tests

- **Arac:** testcontainers-go (PostgreSQL + Redis) + `net/http/httptest`
- **Yaklasim:** Mock YOK. Gercek DB container'lari ayaga kaldir, gercek sorgu calistir
- **Kapsam:**
  - Tam signup -> login -> MFA -> session akisi
  - Token rotation + family revocation DB'de calisiyor mu
  - Rate limiting Redis'te atomik mi
  - Audit log hash chain DB'de tutarli mi
  - Blocking hook timeout davranisi (deny_on_failure)
  - User enumeration korumasi (ayni hata mesaji + ayni response time)
  - Account lockout (10 basarisiz -> 30dk lockout)
  - GDPR cryptographic erasure (user sil -> log chain bozulmamali)

```go
// Testcontainers setup
func TestAuthFlow(t *testing.T) {
    ctx := context.Background()
    pgC, _ := postgres.Run(ctx, "postgres:16")
    redisC, _ := redis.Run(ctx, "redis:7")
    defer pgC.Terminate(ctx)
    defer redisC.Terminate(ctx)
    // ... test against real DB + Redis
}
```

**Go native fuzzing (Katman 4b):**
```go
// go test -fuzz=FuzzLoginInput
func FuzzLoginInput(f *testing.F) {
    f.Add("user@test.com", "password123")
    f.Fuzz(func(t *testing.T, email, password string) {
        req := httptest.NewRequest("POST", "/auth/login",
            strings.NewReader(fmt.Sprintf(`{"email":"%s","password":"%s"}`, email, password)))
        rec := httptest.NewRecorder()
        handler.ServeHTTP(rec, req)
        // Crash olmamali, 400 veya 401 donmeli
        assert.Contains(t, []int{400, 401, 429}, rec.Code)
    })
}
```

#### Katman 5: Contract Tests

- **Arac:** pact-go v2 (Go provider verification) + Pact JS (TypeScript SDK consumer tests)
- **Amac:** SDK'lar <-> Go Server API uyumu garanti
- **Ne zaman:** SDK veya API degisikliklerinde otomatik calisir
- **Kapsam:** Custom API'ler (hooks, admin endpoints, custom claims). OAuth2/OIDC standart flow'lari Pact ile test edilmez (Pact'in kendi tavsiyesi — standartlar zaten iyi tanimli)
- Consumer-driven: Client SDK beklenen API seklini tanimlar, server dogrular

#### Katman 6: DAST (Dynamic Application Security Testing)

- **Arac:** OWASP ZAP
- **Yaklasim:** Calisan sunucuya karsi otomatik saldiri simulasyonu
- **Baseline scan:** Her PR'da (hizli, pasif tarama)
- **Active scan:** Aylik (tam saldiri simulasyonu — SQL injection, XSS, CSRF, header eksiklikleri)
- **CI/CD entegrasyonu:** ZAP Docker image, baseline scan API endpoint'lerine karsi
- **Claude Security ile farki:** ZAP pattern matching yapar, Claude baglam anlar. Birbirini tamamlar

#### Katman 7: E2E Tests

- **Arac:** Playwright
- **Kapsam:**
  - OAuth redirect/callback tam akisi (multi-tab, cross-domain)
  - WebAuthn registration (virtual authenticator ile)
  - MFA enrollment QR -> TOTP dogrulama
  - Dashboard login -> kullanici listesi -> detay
  - Session timeout sonrasi redirect
  - Password reset tam akisi (email -> link -> yeni sifre)
- **Auth state reuse:** Global setup'ta login ol, tum testlerde kullan (her testte login olma)

#### Katman 8: Mutation Testing

- **Arac:** go-gremlins / go-mutesting
- **Amac:** Testlerin GERCEKTEN guvenlik buglarini yakalayip yakalamadigini olcer
- **Nasil calisir:** Kodu otomatik degistirir (if tersine cevir, validation sil, return degerini degistir), testlerin bunu yakalayip yakalamadigini kontrol eder
- **Hedef:** Guvenlik-kritik modullerde (token validation, password hashing, authorization checks) **%80+ mutation score**
- **Code coverage yalan soyler, mutation score soylemez**

```bash
gremlins unleash --tags "security" ./internal/auth/... ./internal/token/... ./internal/session/...
```

#### Katman 9: API Fuzzing

- **Arac:** Microsoft RESTler
- **Nasil calisir:** OpenAPI spec'i okur, endpoint'ler arasi bagimliliklari cikarir (create user -> login -> token al -> resource eris), rastgele ama anlamli request zincirleri uretir
- **Bulduklari:** Auth bypass, cross-user resource erisimi, beklenmeyen input'larda crash, information leakage
- **Referans:** GitLab'da 28 bug buldu, auth bypass dahil

#### Katman 10: Chaos Testing

- **Arac:** Toxiproxy + Testcontainers
- **Senaryolar:**
  - Redis coktu -> rate limiter ne yapiyor? (fail-closed olmali)
  - DB baglanti havuzu doldu -> login calisiyor mu?
  - Hook endpoint 15sn cevap vermedi -> deny_on_failure calisiyor mu?
  - Network partition -> token validation calisiyor mu? (JWT self-contained, calismali)
  - Redis latency 500ms -> session performansi?
- **Amac:** Production'da degil, test ortaminda ariza simule et

#### Katman 11: Load Tests

- **Arac:** Grafana k6
- **SLO'lar:**
  - Login endpoint p99 < 500ms (1000 concurrent user)
  - Token refresh p99 < 100ms
  - Rate limiter baskisi altinda dogru calisiyor mu
  - 50 farkli IP'den ayni hesaba saldiri -> hesap kilitlenmeli
- **Reporting:** k6 Cloud veya InfluxDB + Grafana dashboard

#### Katman 12: Conformance Tests

- **Araclar:** OpenID Foundation conformance suite, FIDO Alliance conformance tools
- **Kapsam:** Protokol uyumu — kendi testlerimizi yazmiyoruz, sertifika kurumlarinin test setlerini calistiriyoruz
- **OpenID Connect:** Basic OP, Config OP, Dynamic OP profilleri
- **FIDO2:** Attestation format dogrulama, signature verification, counter validation
- **FAPI 2.0:** PAR, PKCE, DPoP, sender-constrained token dogrulama

### 43.3 Ne Zaman Ne Calisir?

| Tetikleme | Calisan Testler | Tahmini Sure |
|-----------|-----------------|--------------|
| Her `git push` | Unit + property-based + lint | ~30sn |
| Her PR | + AI Security Review + integration + contract + DAST baseline | ~5dk |
| PR merge to main | + E2E + mutation (security modules) | ~15dk |
| Haftalik (CI cron) | + Full mutation + fuzzing (RESTler) + load test | ~1-2 saat |
| Aylik | + Chaos testing + full DAST active scan | ~4 saat |
| Release oncesi | + Conformance suites (OpenID, FIDO2, FAPI) | ~1 saat |
| Yillik | 3rd party penetration test (harici firma) | Harici |
| Development sirasinda | `claude /security-review` (manuel, istege bagli) | ~2-5dk |

### 43.4 OWASP ASVS v5.0 Hedefi

**Level 2** (hassas veri iceren uygulamalar — bizim icin uygun). Ileriki fazlarda Level 3 (critical applications — finansal islemler aktif olunca).

Kritik bolumler:
- V6.2: Password Security
- V6.3: General Authentication Security
- V6.4: Authentication Factor Lifecycle and Recovery
- V6.5: Multi-factor Authentication
- V6.6: Out-of-Band Authentication
- V6.7: Cryptographic Authentication
- V7.1-V7.6: Session Management

### 43.5 Sertifika Kanit Uretimi

Testlerimiz asagidaki sertifika kanitlarini otomatik uretir:

| Kanit | Kaynak | Sertifika |
|-------|--------|-----------|
| CI/CD pipeline loglari (test gecti/kaldi) | GitHub Actions | SOC 2, ISO 27001 |
| Coverage raporlari (line + branch + mutation score) | `go test -cover` + go-gremlins | SOC 2 |
| DAST tarama raporlari | OWASP ZAP (HTML/JSON) | SOC 2, PCI DSS, ISO 27001 |
| AI security review raporlari | Claude Code Security Review | SOC 2, ISO 27001 |
| Remediation tracker (bug -> fix -> retest) | GitHub Issues + PR linkage | SOC 2, PCI DSS |
| Conformance test sonuclari | OpenID/FIDO2 suite output | OpenID Cert, FIDO2 Cert |
| Load test raporlari | k6 JSON output | SOC 2 (Availability) |
| Chaos test sonuclari | Toxiproxy logs | SOC 2 (Availability), DORA |
| Pentest raporu (yillik) | Harici firma | SOC 2, PCI DSS, ISO 27001 |
| Test plani (versiyonlanmis, her release) | Markdown/Confluence | ISO 27001 (Annex A 8.29) |

### 43.6 Coverage Hedefleri

| Modul | Line Coverage | Branch Coverage | Mutation Score |
|-------|--------------|-----------------|----------------|
| Password hashing & validation | %95+ | %90+ | %85+ |
| Token issuance & validation | %95+ | %90+ | %85+ |
| Session management | %90+ | %85+ | %80+ |
| Rate limiting | %90+ | %85+ | %80+ |
| Audit log + hash chain | %95+ | %90+ | %85+ |
| Hook pipeline | %90+ | %85+ | %80+ |
| Risk engine | %85+ | %80+ | %75+ |
| CRUD / admin endpoints | %80+ | %75+ | %70+ |
| SDK'lar | %85+ | %80+ | %75+ |
| Genel ortalama | %90+ | %85+ | %80+ |

---


## 44. Dashboard (Next.js)

> Dashboard, Go server'in Admin API'sini tuketir. Self-hosted'da `localhost:3001`'de calisir.
> Go server + Dashboard birlikte `docker compose up` ile ayaga kalkar.
> Ayni dashboard ileride SaaS'ta da kullanilir.

### 44.1 Ilk Acilis (Setup Wizard)

```
1. docker compose up
2. Browser: http://localhost:3001
3. "PalAuth'a hosgeldiniz — admin hesabinizi olusturun"
   - Email + sifre
4. "Ilk projenizi olusturun"
   - Proje adi: "My App"
   - API key'ler otomatik uretilir ve gosterilir
5. "Quickstart"
   - Framework sec (Next.js, React, NestJS, Go, Flutter...)
   - Kopyala-yapistir ornek kod (API key'ler dolu)
   - "Test edin" butonu — dashboard'da canli login izle
```

### 44.2 Erisim & Yetkilendirme

Dashboard'a giris: Email + sifre (Go server'in kendi auth'u — dogfooding).

| Rol | Projeler | Kullanicilar | Config | API Key | Audit Log |
|-----|----------|-------------|--------|---------|-----------|
| Owner | CRUD | Tam | Tam | Olustur/Rotate/Sil | Tam |
| Admin | Goruntule | Tam | Tam | Goruntule | Tam |
| Developer | Goruntule | Goruntule | Salt okunur | Goruntule | Goruntule |

### 44.3 Sayfa Yapisi

**Projects (Ana Sayfa)**
- Proje listesi (kart gorunumu)
- Her kartta: proje adi, aktif kullanici sayisi, son 24 saat login trendi
- "Yeni Proje Olustur" butonu
- Proje secince proje detay sayfasina gider

**Project Detail -> Overview**
- Aktif kullanici (MAU), login basari/basarisizlik (24 saat)
- Aktif session sayisi
- Alert'ler (brute force, anomali)
- API key'ler (pk_test/sk_test/pk_live/sk_live — tikla kopyala, default gizli)

**Project Detail -> Users**
- Liste: arama, filtreleme (auth yontemi, MFA durumu, son giris, banned)
- Detay: profil, session'lar, login gecmisi, MFA enrollments, custom claims
- Aksiyonlar: ban/unban, password reset, MFA reset, delete
- Import (CSV/JSON) + Export (GDPR)

**Project Detail -> Authentication**
- Toggle switch'ler: Email+Password, Google, Apple, GitHub, Microsoft, Magic Link, Passkeys, SMS OTP, TOTP
- Her provider icin konfigurasyon (Client ID, Secret, redirect URI)
- Password policy: min uzunluk, HIBP check, history
- Session policy: idle timeout, absolute timeout, concurrent limit

**Project Detail -> API Keys**
- Key listesi (pk_test, sk_test, pk_live, sk_live)
- Rotate butonu (yeni key uretir, eskisi grace period sonra gecersiz)
- Ek API key olusturma (scoped, read-only)
- Son kullanim + request sayisi

**Project Detail -> Hooks & Webhooks**
- Blocking hooks: endpoint URL, HMAC secret, failure mode, timeout
- "Test Hook" butonu (ornek payload gonder, response gor)
- Hook cagri loglari (son 100: request/response, latency, status)
- Webhooks: endpoint, event secimi, delivery log, DLQ, replay

**Project Detail -> Audit Logs**
- Real-time log stream
- Filtre: event tipi, kullanici, IP, tarih, sonuc
- Log detay (tam payload)
- Export (JSON/CSV)
- "Verify Integrity" butonu (hash chain dogrulama)

**Project Detail -> Security**
- Risk engine: esik degerleri (allow/step-up/block)
- IP whitelist/blacklist
- Geo-blocking (ulke bazli)
- Bot detection (PoW zorlugu)
- Rate limit ayarlari (endpoint bazinda override)

**Project Detail -> Analytics**
- Auth yontemi dagilimi (pie chart)
- MFA adoption orani (trend)
- Login basari/basarisizlik trendi (line chart)
- Session dagilimi: cihaz, ulke, tarayici
- Risk score dagilimi (histogram)

**Project Detail -> Settings**
- Proje adi, aciklama
- Custom domain + TLS durumu
- Email template editoru (visual + HTML)
- Email provider (SMTP, SES, SendGrid)
- SMS provider (Twilio)
- Branding: logo, renkler
- CORS allowed origins
- Redirect URL whitelist
- Dil ayarlari

**Global -> Admin Users**
- Dashboard erisim olan admin kullanicilari
- Davet gonder, rol degistir

### 44.4 Teknoloji

- Next.js 15 (App Router)
- shadcn/ui + Tailwind CSS
- React Query (Go Admin API'yi tuketir)
- Recharts (analytics grafikleri)

### 44.5 Admin API Endpoint'leri (Go Server)

Dashboard bu endpoint'leri tuketir. Tum fazlardaki endpoint'lerin tam listesi:

```
# Setup + Admin Auth (Faz 0)
POST   /admin/setup                          → Ilk kurulum
POST   /admin/login                          → Admin login → admin JWT
GET    /admin/users                          → Dashboard admin kullanicilari
POST   /admin/users/invite                   → Admin davet

# Project + API Keys (Faz 0)
GET    /admin/projects                       → Proje listesi
POST   /admin/projects                       → Yeni proje olustur
GET    /admin/projects/:id                   → Proje detay
PUT    /admin/projects/:id/config            → Konfigurasyon guncelle
DELETE /admin/projects/:id                   → Proje sil
GET    /admin/projects/:id/keys              → API key listesi
POST   /admin/projects/:id/keys/rotate       → API key rotate

# Users (Faz 0)
GET    /admin/projects/:id/users             → Kullanici listesi
POST   /admin/projects/:id/users             → Kullanici olustur
GET    /admin/projects/:id/users/:uid        → Kullanici detay
PUT    /admin/projects/:id/users/:uid        → Kullanici guncelle
DELETE /admin/projects/:id/users/:uid        → GDPR erasure
POST   /admin/projects/:id/users/:uid/ban    → Ban
POST   /admin/projects/:id/users/:uid/unban  → Unban
POST   /admin/projects/:id/users/:uid/reset-password → Admin password reset
GET    /admin/projects/:id/users/:uid/export → GDPR export (Faz 3)
GET    /admin/projects/:id/users/:uid/consents → Consent gecmisi (Faz 3)

# Audit + Analytics (Faz 0)
GET    /admin/projects/:id/audit-logs        → Audit log sorgula
POST   /admin/projects/:id/audit-logs/verify → Hash chain dogrula
GET    /admin/projects/:id/audit-logs/export → JSON/CSV export
GET    /admin/projects/:id/analytics         → Analytics

# Hooks + Webhooks (Faz 1)
GET    /admin/projects/:id/hooks             → Hook listesi
POST   /admin/projects/:id/hooks             → Hook olustur
PUT    /admin/projects/:id/hooks/:hid        → Hook guncelle
DELETE /admin/projects/:id/hooks/:hid        → Hook sil
POST   /admin/projects/:id/hooks/:hid/test   → Hook test
GET    /admin/projects/:id/hooks/:hid/logs   → Hook loglari
GET    /admin/projects/:id/webhooks          → Webhook listesi
POST   /admin/projects/:id/webhooks          → Webhook olustur
PUT    /admin/projects/:id/webhooks/:wid     → Webhook guncelle
DELETE /admin/projects/:id/webhooks/:wid     → Webhook sil
GET    /admin/projects/:id/webhooks/:wid/deliveries → Delivery loglar
GET    /admin/projects/:id/webhooks/dlq      → Dead letter queue
POST   /admin/projects/:id/webhooks/dlq/:did/retry → DLQ retry
POST   /admin/projects/:id/webhooks/replay   → Event replay

# Organizations (Faz 2)
POST   /admin/projects/:id/organizations              → Org olustur
GET    /admin/projects/:id/organizations              → Org listesi
GET    /admin/projects/:id/organizations/:oid         → Org detay
PUT    /admin/projects/:id/organizations/:oid         → Org guncelle
DELETE /admin/projects/:id/organizations/:oid         → Org sil
POST   /admin/projects/:id/organizations/:oid/members → Member ekle
PUT    /admin/projects/:id/organizations/:oid/members/:uid → Rol degistir
DELETE /admin/projects/:id/organizations/:oid/members/:uid → Member cikar
POST   /admin/projects/:id/organizations/:oid/invitations → Davet
POST   /admin/projects/:id/organizations/:oid/domain/verify → Domain dogrula

# OAuth Clients (Faz 2)
POST   /admin/projects/:id/oauth-clients              → Client olustur
GET    /admin/projects/:id/oauth-clients              → Client listesi
PUT    /admin/projects/:id/oauth-clients/:cid         → Client guncelle
DELETE /admin/projects/:id/oauth-clients/:cid         → Client sil

# Key Rotation (Faz 2)
POST   /admin/keys/rotate                   → Manuel key rotation
GET    /admin/keys                          → Key listesi

# SSO + SCIM (Faz 3)
POST   /admin/projects/:id/organizations/:oid/sso     → SSO connection
GET    /admin/projects/:id/organizations/:oid/sso     → SSO listesi
PUT    /admin/projects/:id/organizations/:oid/sso/:sid → SSO guncelle
DELETE /admin/projects/:id/organizations/:oid/sso/:sid → SSO sil

# API Keys + Service Accounts (Faz 3)
POST   /admin/projects/:id/api-keys                   → Scoped API key
DELETE /admin/projects/:id/api-keys/:kid              → Key revoke
POST   /admin/projects/:id/service-accounts           → Service account
POST   /admin/projects/:id/service-accounts/:said/rotate → Credential rotate
DELETE /admin/projects/:id/service-accounts/:said     → Revoke

# Breach + Compliance (Faz 3)
GET    /admin/projects/:id/breach-status              → Breach durumu
POST   /admin/projects/:id/breach-check               → Manuel check

# Impersonation (Faz 4)
POST   /admin/projects/:id/users/:uid/impersonate     → Impersonate
POST   /admin/impersonation/end                       → Impersonation sonlandir

# Custom Domains (Faz 4)
POST   /admin/projects/:id/domains                    → Domain ekle
GET    /admin/projects/:id/domains                    → Domain listesi
DELETE /admin/projects/:id/domains/:did               → Domain kaldir
PUT    /admin/projects/:id/branding                   → Branding config

# Migration (Faz 4)
POST   /admin/projects/:id/migrations                 → Import baslat
GET    /admin/projects/:id/migrations                 → Job listesi
GET    /admin/projects/:id/migrations/:mid            → Job detay

# Agents (Faz 5)
POST   /admin/projects/:id/agents                     → Agent olustur
GET    /admin/projects/:id/agents                     → Agent listesi
DELETE /admin/projects/:id/agents/:aid                → Agent revoke
```

Tum admin endpoint'leri `sk_live_*` veya `sk_test_*` key ile authenticate edilir.

---

## 45. SaaS Platform

> SaaS detaylari: [spec-saas.md](spec-saas.md)
