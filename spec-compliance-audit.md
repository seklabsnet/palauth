# spec-compliance.md — Doğruluk Denetim Raporu

> Tarih: 1 Nisan 2026
> Yöntem: Her iddia resmi kaynaklara karşı web araştırmasıyla doğrulandı.

---

## Özet

| Bölüm | Doğru | Kısmen Doğru | Yanlış | Doğrulanamadı |
|-------|-------|-------------|--------|---------------|
| NIST 800-63B-4 | 9 | 1 | 0 | 0 |
| PCI DSS v4.0.1 | 7 | 2 | 0 | 0 |
| FAPI 2.0 | 12 | 1 | 0 | 0 |
| OAuth 2.1 | 6 | 1 | 0 | 0 |
| FIDO2/WebAuthn | 3 | 0 | 0 | 1 |
| PSD2/PSD3 SCA | 7 | 1 | 2 | 0 |
| GDPR | 5 | 0 | 0 | 0 |
| DORA | 5 | 1 | 1 | 0 |
| FIPS 140-3 | 5 | 1 | 0 | 0 |
| ETSI / eIDAS / QES | 2 | 0 | 0 | 0 |
| Rakip Karşılaştırma | 6 | 2 | 2 | 4 |
| **TOPLAM** | **67** | **10** | **5** | **5** |

**Genel Doğruluk: %77 tamamen doğru, %89 doğru+kısmen doğru, %6 yanlış.**

---

## KRİTİK HATALAR (Düzeltilmeli)

### HATA 1: PSD2 — İki inherence faktör iddiası
**Satır:** "İki inherence faktörü izinli (örn: parmak izi + yüz tanıma) — SADECE inherence kategorisinde"
**Gerçek:** Bu YANLIŞ. PSD2/PSD3 SCA, faktörlerin FARKLI bağımsız kategorilerden olmasını zorunlu kılar. İki inherence faktörü (parmak izi + yüz tanıma) bağımsızlık gereksinimini karşılamaz. İki farklı kategoriden faktör gerekir (örn: inherence + possession veya inherence + knowledge).

### HATA 2: PSD2 — Auth code 5dk ömrü iddiası
**Satır:** "Max 5-minute auth code lifetime"
**Gerçek:** PSD2 RTS'de auth code'un kendisi için spesifik 5 dakika ömür sınırı bulunamadı. OTP/code tek kullanımlık olmalı (replay koruması) ama süre sınırı farklı. 5 dakika kuralı session inactivity timeout (Art. 4(3)(d)) ile karıştırılmış olabilir.

### HATA 3: DORA — İş sürekliliği testi 6 aylık iddiası
**Satır:** "İş sürekliliği testi: 6 aylık"
**Gerçek:** Bu YANLIŞ. DORA yıllık test zorunlu kılar (en az yılda bir ve önemli ICT değişikliklerinden sonra). 6 aylık değil. TLPT (Threat-Led Penetration Testing) ise her 3 yılda bir zorunlu.

### HATA 4: Rakip Tablo — Auth0 FAPI iddiası
**Satır:** Auth0 için "FAPI 1" yazılmış
**Gerçek:** Auth0, FAPI 2.0'ı da destekliyor. Sadece FAPI 1 olarak göstermek yanıltıcı. "FAPI 1+2" veya "FAPI 2.0" olarak güncellenmeli.

### HATA 5: Rakip Tablo — Firebase Auth HIPAA iddiası
**Satır:** Firebase Auth için "HIPAA: Evet" yazılmış
**Gerçek:** Firebase Auth, Google Cloud'un HIPAA BAA kapsamında DEĞİL. Google Cloud Identity Platform HIPAA uyumlu olabilir ama Firebase Auth spesifik olarak kapsam dışı.

---

## KISMİ DOĞRU (İyileştirme Önerilir)

### 1. NIST 800-63B-4 — AAL2 phishing-resistant section referansı
**Satır:** "SHALL offer at least one phishing-resistant option (NIST 800-63B-4 Sec 2.2.2)"
**Durum:** Gereksinim doğru, ama section numarası muhtemelen yanlış. Kaynaklar Sec 3.2.5'i referans gösteriyor, Sec 2.2.2 değil. Section numarası doğrulanmalı.

### 2. PCI DSS v4.0.1 Req 8.3.6 — Composition kuralları
**Satır:** "numeric + alfa zorunlu (Req 8.3.6)"
**Durum:** Eksik. Req 8.3.6 aslında büyük harf + küçük harf + sayı + özel karakter karışımı gerektirir. Sadece "numeric + alfa" yazmak eksik kalıyor.

### 3. PCI DSS — Customized Approach ve SAQ ilişkisi
**Satır:** "QSA validation gerekir, SAQ ile kullanılamaz"
**Durum:** Kısmen doğru. SAQ organizasyonları ROC değerlendirmesine geçerek customized approach kullanabilir. Mutlak bir yasak değil, bir yükseltme gereksinimi. Ayrıca Customized Approach ile Compensating Controls farklı mekanizmalar — biri alternatif yaklaşım, diğeri yedek kontrol.

### 4. DORA — Olay bildirimi 24 saat iddiası
**Satır:** "Olay bildirimi (24 saat)"
**Durum:** Kısmen doğru. DORA, majör olarak sınıflandırıldıktan sonra 4 saat içinde ilk bildirim yapılmasını, tespitten itibaren en geç 24 saat içinde bildirilmesini gerektirir. 72 saat içinde ara rapor, 1 ay içinde nihai rapor. Sadece "24 saat" yazmak basitleştirme.

### 5. FAPI 2.0 — Token lifetime section referansı
**Satır:** "Token lifetime: Normative zorunluluk YOK. Sec 6.1 non-normative"
**Durum:** Genel ifade doğru — normatif zorunluluk yok. Ama "Sec 6.1" referansı spesifik olarak doğrulanamadı. İçerik doğru, referans belirsiz.

### 6. OAuth 2.1 — Plain PKCE metodu
**Satır:** "S256 only, plain method kaldırıldı"
**Durum:** Kısmen doğru. Plain metod tamamen kaldırılmadı, ama çok kısıtlandı. Sadece S256 destekleyemeyen kısıtlı cihazlar için izin veriliyor. Pratikte S256 zorunlu.

### 7. FIPS 140-3 — SafeLogic VaaS fiyatlandırması
**Satır:** "VaaS (SafeLogic) — €50K-€150K, ~2 ay"
**Durum:** SafeLogic VaaS gerçek bir hizmet ve ~2 ay süresi doğru görünüyor. Ama €50K-€150K fiyat aralığı publik kaynaklardan doğrulanamadı (fiyatlar talep üzerine veriliyor).

### 8. Altyapı — İş sürekliliği testi 6 aylık (Bölüm 13)
**Satır:** "DR testi: 6 ayda bir (SOC 2 kanıtı)"
**Durum:** SOC 2 yıllık DR testi gerektirir. 6 aylık daha iyi bir pratik olabilir ama SOC 2'nin zorunlu kıldığı minimum yıllık. DORA hatası ile tutarlı bir karışıklık var.

### 9. Rakip Tablo — Birden fazla doğrulanamayan iddia
Descope FIDO2 sertifikası, SuperTokens SOC 2, WorkOS ISO 27001 yokluğu gibi birçok iddia publik kaynaklardan kesin doğrulanamadı. Bunlar sürekli değişen bilgiler, düzenli güncelleme gerektirir.

### 10. PSD2/PSD3 — PSR SCA Articles
**Satır:** "SCA kuralları artık PSR Articles 85-89'da"
**Durum:** Genel olarak doğru — Article 85 SCA çerçevesini başlatıyor. Ama tam article dağılımı kamuya açık nihai metinlerden kesin doğrulama zor.

---

## BÖLÜM BAZLI DETAY

### NIST 800-63B-4 (9/10 doğru)
| # | İddia | Sonuç |
|---|-------|-------|
| 1 | AAL1: Absolute SHALL, SHOULD 30 gün. Idle gereksinim yok | ✅ Doğru |
| 2 | AAL2: Idle SHOULD 1 saat, Absolute SHOULD 24 saat | ✅ Doğru |
| 3 | AAL2 Rev 3→4 farkları: 30dk→1sa, 12sa→24sa, SHALL→SHOULD | ✅ Doğru |
| 4 | AAL3: Idle SHOULD 15dk, Absolute SHALL 12 saat | ✅ Doğru |
| 5 | AAL2 phishing-resistant SHALL — Sec 2.2.2 | ⚠️ Gereksinim doğru, section no muhtemelen yanlış |
| 6 | Password min 15 char (single-factor), 8 char (MFA) | ✅ Doğru |
| 7 | Composition rules SHALL NOT | ✅ Doğru |
| 8 | Periodic rotation SHALL NOT | ✅ Doğru |
| 9 | Compromised password check SHALL | ✅ Doğru |
| 10 | AAL3 software-only authenticators DO NOT qualify | ✅ Doğru |

### PCI DSS v4.0.1 (7/9 doğru)
| # | İddia | Sonuç |
|---|-------|-------|
| 1 | Req 8.3.4: 10 başarısız → 30dk lockout | ✅ Doğru |
| 2 | Req 8.3.6: 12 char + numeric+alfa | ⚠️ Eksik — özel karakter de gerekli |
| 3 | Req 8.3.7: Son 4 şifre tekrar yasak | ✅ Doğru |
| 4 | Req 8.3.9: MFA aktifse rotation gerekmez | ✅ Doğru |
| 5 | Req 8.2.6: 90 gün inaktif → devre dışı | ✅ Doğru |
| 6 | Req 8.6.1-8.6.3: Service account gereksinimleri | ✅ Doğru |
| 7 | Req 6.4.2: WAF zorunlu | ✅ Doğru |
| 8 | v4.0 RETIRED 31 Aralık 2024 | ✅ Doğru |
| 9 | Customized Approach + SAQ ilişkisi | ⚠️ Basitleştirilmiş — SAQ→ROC geçişi mümkün |

### FAPI 2.0 (12/13 doğru)
| # | İddia | Sonuç |
|---|-------|-------|
| 1 | Final, Şubat 2025 | ✅ Doğru (22 Şubat 2025) |
| 2 | Sadece PS256, ES256, EdDSA. RS256 YASAK | ✅ Doğru |
| 3 | Auth code max 60sn (Sec 5.3.2.1 SHALL) | ✅ Doğru |
| 4 | PAR request_uri < 600sn (Sec 5.3.2.2 SHALL) | ✅ Doğru |
| 5 | Sadece confidential client | ✅ Doğru |
| 6 | HTTP 307 YASAK, sadece 303 | ✅ Doğru |
| 7 | RFC 9207 iss parameter zorunlu | ✅ Doğru |
| 8 | Sender-constrained token zorunlu (mTLS/DPoP) | ✅ Doğru |
| 9 | PKCE S256 zorunlu | ✅ Doğru |
| 10 | Refresh token rotation SHALL NOT | ✅ Doğru |
| 11 | JARM base profile'da gerekli değil | ✅ Doğru |
| 12 | s_hash kaldırıldı, PKCE ile değiştirildi | ✅ Doğru |
| 13 | Token lifetime normatif zorunluluk yok | ⚠️ İçerik doğru, Sec 6.1 referansı doğrulanamadı |

### OAuth 2.1 (6/7 doğru)
| # | İddia | Sonuç |
|---|-------|-------|
| 1 | draft-ietf-oauth-v2-1-15, Mart 2026 | ✅ Doğru |
| 2 | PKCE zorunlu, S256 only, plain kaldırıldı | ⚠️ Plain tamamen kaldırılmadı, çok kısıtlandı |
| 3 | Implicit grant kaldırıldı | ✅ Doğru |
| 4 | ROPC grant kaldırıldı | ✅ Doğru |
| 5 | Refresh token: sender-constrained veya one-time use | ✅ Doğru |
| 6 | Bearer token URI query parameter YASAK | ✅ Doğru |
| 7 | Exact redirect URI string matching zorunlu | ✅ Doğru |

### FIDO2/WebAuthn (3/4 doğru)
| # | İddia | Sonuç |
|---|-------|-------|
| 1 | BE/BS flags: BE=0→AAL3, BE=1→AAL2 | ✅ Doğru |
| 2 | SafetyNet Mayıs 2025 kapandı, android-key aktif | ✅ Doğru |
| 3 | Challenge 16+ byte, single-use | ✅ Doğru |
| 4 | compound format Sec 8.9, IANA'da değil | ❓ Doğrulanamadı |

### PSD2/PSD3 SCA (7/11 doğru)
| # | İddia | Sonuç |
|---|-------|-------|
| 1 | İki bağımsız faktör (knowledge/possession/inherence) | ✅ Doğru |
| 2 | Dynamic linking (tutar + alıcı) | ✅ Doğru |
| 3 | Auth code max 5dk | ❌ Doğrulanamadı — muhtemelen karışıklık |
| 4 | Max 5 başarısız deneme | ✅ Doğru |
| 5 | Max 5dk session inactivity timeout | ✅ Doğru |
| 6 | PSD3/PSR politik anlaşma 27 Kasım 2025 | ✅ Doğru |
| 7 | PSR yürürlük H2 2027 - başı 2028 | ✅ Doğru |
| 8 | SCA kuralları PSR Articles 85-89 | ✅ Doğru |
| 9 | İki inherence faktörü izinli | ❌ YANLIŞ — bağımsızlık gereksinimini karşılamaz |
| 10 | SCA erişilebilirlik yasal hak | ✅ Doğru |
| 11 | SCA delegasyonu = outsourcing | ✅ Doğru (PSD3 açıklaması) |

### GDPR (5/5 doğru)
| # | İddia | Sonuç |
|---|-------|-------|
| 1 | Right to erasure: Art. 17 | ✅ Doğru |
| 2 | Data portability: Art. 20 | ✅ Doğru |
| 3 | Breach notification: 72 saat, Art. 33 | ✅ Doğru |
| 4 | DPIA: Art. 35 | ✅ Doğru |
| 5 | International transfers: Chapter V, Art. 44-49 | ✅ Doğru |

### DORA (5/7 doğru)
| # | İddia | Sonuç |
|---|-------|-------|
| 1 | 17 Ocak 2025 yürürlük | ✅ Doğru |
| 2 | Finansal kurum cezası: yıllık cironun %2'si (Art. 50-52) | ✅ Doğru |
| 3 | CTPP: günlük cironun %1'i + €5M | ✅ Doğru |
| 4 | Olay bildirimi: 24 saat | ⚠️ Basitleştirilmiş — 4 saat ilk bildirim, 24 saat mutlak üst sınır |
| 5 | İş sürekliliği testi: 6 aylık | ❌ YANLIŞ — DORA yıllık test zorunlu kılıyor |
| 6 | Chapter VI, Art. 45 bilgi paylaşımı | ✅ Doğru |
| 7 | Sözleşme gereksinimleri Art. 28-30 | ✅ Doğru |

### FIPS 140-3 (5/6 doğru)
| # | İddia | Sonuç |
|---|-------|-------|
| 1 | FIPS 140-2 sunset 21 Eylül 2026 | ✅ Doğru |
| 2 | Go 1.24 native FIPS, sertifika A6650, cgo gereksiz | ✅ Doğru |
| 3 | Onaylı algoritmalar listesi | ✅ Doğru (P-521 de eklenebilir) |
| 4 | Yasaklı algoritmalar listesi | ✅ Doğru |
| 5 | Argon2id FIPS-approved değil, PBKDF2 600K+ iteration | ✅ Doğru |
| 6 | SafeLogic VaaS €50K-€150K, ~2 ay | ⚠️ Hizmet ve süre doğru, fiyat doğrulanamadı |

### ETSI / eIDAS / QES (2/2 doğru)
| # | İddia | Sonuç |
|---|-------|-------|
| 1 | ETSI TS 119 461 Ağustos 2027 zorunlu (EU 2025/1566) | ✅ Doğru |
| 2 | CSC API = ETSI TS 119 432 | ✅ Doğru |

### Rakip Karşılaştırma Tablosu (6/14 kesin doğru)
| Sağlayıcı | İddia | Sonuç |
|-----------|-------|-------|
| Auth0 | FAPI 1 | ❌ Auth0 FAPI 2.0 da destekliyor |
| Auth0 | OpenID, SOC 2, ISO, HIPAA, PSD2 | ✅ Doğru |
| Firebase | HIPAA: Evet | ❌ Firebase Auth HIPAA BAA kapsamında değil |
| Firebase | SOC 2, ISO 27001, FedRAMP* | ✅ Doğru (Google Cloud'dan) |
| Supabase | SOC 2, HIPAA, Self-hosted | ✅ Doğru |
| Descope | SOC 2, ISO, PCI DSS, FedRAMP High | ✅ Doğru |
| Descope | FIDO2 Certified | ❓ Doğrulanamadı |
| Hanko | FIDO2 Certified, Self-hosted | ✅ Doğru |
| Zitadel | OpenID, SOC 2, ISO 27001, Self-hosted | ✅ Doğru |
| Ory | OpenID (Hydra), SOC 2, ISO 27001 | ✅ Doğru |
| SuperTokens | SOC 2 | ❓ Doğrulanamadı |

---

## ÖNERİLEN DÜZELTMELER

### Zorunlu Düzeltmeler (5 adet)

1. **Bölüm 6, PSD3 SCA:** "İki inherence faktörü izinli" ifadesini kaldır veya düzelt. PSD2/PSD3 SCA bağımsız kategorilerden faktör gerektirir.

2. **Bölüm 6, PSD2 SCA:** "Max 5-minute auth code lifetime" ifadesini doğrula veya kaldır. PSD2 RTS'de auth code için spesifik süre sınırı bulunamadı. OTP/code tek kullanımlık olmalı ama 5dk kuralı farklı bir bağlamda.

3. **Bölüm 8, DORA:** "İş sürekliliği testi (6 aylık)" → "İş sürekliliği testi (yıllık)" olarak düzelt. Bölüm 13'te de "DR testi: 6 ayda bir" aynı şekilde düzeltilmeli.

4. **Bölüm 14, Rakip Tablo:** Auth0 satırı "FAPI 1" → "FAPI 2.0" olarak güncelle.

5. **Bölüm 14, Rakip Tablo:** Firebase Auth satırı "HIPAA: Evet" → "Hayır*" olarak güncelle (*Firebase Auth, Google Cloud HIPAA BAA kapsamında değil. Cloud Identity Platform ile karıştırılmamalı.)

### Önerilen İyileştirmeler (5 adet)

6. **Bölüm 2:** AAL2 phishing-resistant section referansını "Sec 2.2.2" yerine doğru section numarasıyla güncelle.

7. **Bölüm 3:** PCI DSS Req 8.3.6 açıklamasını "numeric + alfa" yerine "büyük harf + küçük harf + sayı + özel karakter" olarak genişlet.

8. **Bölüm 8:** DORA olay bildirimi "24 saat" → "4 saat ilk bildirim, max 24 saat tespitten itibaren" olarak detaylandır.

9. **Bölüm 9:** FIPS approved algoritmalar listesine ECDSA P-521'i ekle.

10. **Bölüm 14:** Rakip tablosuna "Son güncelleme: [tarih]" notu ekle — bu bilgiler hızla eskiyor.
