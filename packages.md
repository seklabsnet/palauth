# PalAuth — Go Paket Referansi (Final — Degismeyecek)

> Tum paketler Mart 2026 itibariyle dogrulanmistir.
> **Tum paketler Faz 0'dan itibaren go.mod'a eklenir. Hicbir fazda paket degisikligi yapilmaz.**
> Faz 0'da kullanilmayan paketler bile import edilir — sonraki fazlarda sadece internal/ altinda yeni dosyalar eklenir, go.mod degismez.

---

## Core

| Kategori | Paket | Versiyon | Stars | Neden |
|----------|-------|---------|-------|-------|
| Router | `go-chi/chi` | v5.2.5 | 21.8K | Chi-native, net/http uyumlu, middleware ecosystem |
| DB driver | `jackc/pgx` | v5.8.0 | 13.5K | En iyi PG driver, LISTEN/NOTIFY, pgxpool |
| Query codegen | `sqlc-dev/sqlc` | v1.30.0 | 17.2K | Type-safe SQL, pgx uzerine generate |
| Migrations | `pressly/goose` | v3.27.0 | 10.3K | SQL + Go migrations, aktif (Sub 2026) |
| Redis | `redis/go-redis` | v9.18.0 | 22K | Predictable latency, battle-tested |
| JOSE (JWK/JWE/JWS) | `go-jose/go-jose` | v4.1.3 | 492 | Full JOSE suite — JWKS, key rotation, encrypted tokens |
| JWT (basit) | `golang-jwt/jwt` | v5.3.1 | 8.9K | Access token sign/verify, 14.8K importer |
| Password hash | `alexedwards/argon2id` | latest | ~1K | Argon2id wrapper, PHC format, secure defaults |
| Validation | `go-playground/validator` | v10 | 19.8K | Struct tag-based, cok aktif |
| Config | `knadh/koanf` | v2.3.4 | 3.9K | Viper'dan %313 kucuk, modular |
| Logging | `log/slog` (stdlib) | Go 1.26 | — | Standart, pluggable handler |
| Logging (ek) | `samber/slog-multi` | latest | — | Fan-out, filtering, routing |
| Rate limiting | `go-chi/httprate` | latest | 438 | Chi-native sliding window |
| Rate limit (dist) | `go-chi/httprate-redis` | latest | — | Redis backend, multi-instance |
| CORS | `rs/cors` | v1.11.1 | 2.8K | Router-agnostic, go-chi/cors'dan daha aktif |
| ID generation | `google/uuid` (UUIDv7) | latest | 6K | RFC 9562, PG native uuid, time-ordered |
| Metrics | `prometheus/client_golang` | v1.23.2 | 5.9K | Standart |
| OpenAPI codegen | `oapi-codegen/oapi-codegen` | v2.6.0 | 8.1K | Spec-first, Chi first-class |
| HTTP client | stdlib `net/http` | Go 1.26 | — | Tam kontrol, guvenlik icin onemli |
| Error handling | stdlib `errors` + domain types | Go 1.26 | — | Basit, custom error codes |
| Context | stdlib `context` | Go 1.26 | — | Request-scoped metadata |
| Graceful shutdown | stdlib `signal` + `sync` | Go 1.26 | — | 20-30 satir, kutuphane gereksiz |

---

## Auth Protokolleri

| Kategori | Paket | Versiyon | Stars | Not |
|----------|-------|---------|-------|-----|
| TOTP | `pquerna/otp` | v1.5.0 | 2.8K | TOTP + HOTP, SHA1/256/512, custom digits |
| QR Code | `skip2/go-qrcode` | latest | 2.9K | Basit, stabil — TOTP enrollment QR icin yeterli |
| OAuth2 client | `golang.org/x/oauth2` | v0.36.0 | 5.8K | Native PKCE destegi (GenerateVerifier, S256ChallengeOption) |

---

## Risk & Device

| Kategori | Paket | Versiyon | Stars | Not |
|----------|-------|---------|-------|-----|
| OIDC Provider | `zitadel/oidc` | v3.45.6 | 1.7K | OpenID Certified, OP + RP, cok aktif |
| WebAuthn | `go-webauthn/webauthn` | v0.16.1 | 1.2K | FIDO2 Conformant, passkey destegi |
| IP Geolocation | `oschwald/geoip2-golang` | v2.1.0 | 2.2K | MaxMind GeoLite2 wrapper (City, Country, ASN) |
| User-Agent parse | `mileusna/useragent` | latest | ~1K | Device fingerprinting icin UA parse |
| Device fingerprint | Custom (compose) | — | — | UA + IP + GeoIP + client-side FingerprintJS |
| Events (later) | `ThreeDotsLabs/watermill` | v1.5.1 | 9.6K | Kafka, Redis Streams, NATS, in-memory |

---

## Financial-Grade & Enterprise

| Kategori | Paket | Versiyon | Stars | Not |
|----------|-------|---------|-------|-----|
| DPoP | `AxisCommunications/go-dpop` | v1.1.2 | 12 | Tek Go DPoP lib. Kucuk — vendor/fork dusun |
| SAML 2.0 | `crewjam/saml` | v0.5.1 | 1K | CVE'ler fixli (v0.4.14+). XXE Go'da mumkun degil |
| SCIM 2.0 | `elimity-com/scim` | HEAD (pin commit) | 230 | Tek Go SCIM server. IdP'lerle test et |
| Play Integrity | `google.golang.org/api/playintegrity/v1` | latest | — | Resmi Google API client |
| App Attest | `splitsecure/go-app-attest` | latest | 19 | En aktif Go App Attest lib. Kodu audit et |
| CBOR (App Attest) | `fxamacker/cbor` | v2 | 829 | WebAuthn/App Attest attestation parse |
| PAR | Custom (zitadel/oidc destekler) | — | — | zitadel/oidc v3'te PAR destegi var |

---

## Scale & Infra

| Kategori | Paket | Versiyon | Stars | Not |
|----------|-------|---------|-------|-----|
| ACME/TLS | `caddyserver/certmagic` | v0.25.2 | 5.5K | Auto HTTPS, renewal, distributed locking, wildcard |
| Tracing | `go.opentelemetry.io/otel` | latest | — | OpenTelemetry standart |
| Error tracking | `getsentry/sentry-go` | latest | — | Sentry entegrasyonu (opsiyonel) |
| FIPS 140-3 | Go 1.26 native module | A6650 | — | cgo gereksiz, pure Go |

---

## Testing

| Kategori | Paket | Versiyon | Stars | Not |
|----------|-------|---------|-------|-----|
| Test framework | `stretchr/testify` | v1.11.1 | 25.8K | require + assert |
| Mock generation | `vektra/mockery` | v3.7.0 | 7K | Interface'den mock, v3: 5-10x hizli |
| Integration test | `testcontainers/testcontainers-go` | v0.41.0 | 4.7K | Gercek PG + Redis container |
| Property-based | `flyingmutant/rapid` | latest | ~700 | Otomatik shrinking, Hypothesis-inspired |
| Fuzzing | Go native (`go test -fuzz`) | Go 1.26 | — | Coverage-guided, built-in |
| DAST | OWASP ZAP (external) | latest | — | Docker image ile CI/CD |
| API fuzzing | Microsoft RESTler (external) | latest | — | Stateful REST API fuzzer |
| Mutation | go-gremlins (external) | latest | — | Mutation testing |
| Load | Grafana k6 (external) | latest | — | JS/TS scripts, Go extensions |
| E2E | Playwright (external) | latest | — | Browser flows (Next.js dashboard) |
| AI Security | Claude Code Security Review | latest | — | GitHub Action, context-aware |

---

## Paket Secim Prensipleri

1. **stdlib oncelikli** — stdlib yetiyorsa harici paket ekleme (errors, context, signal, net/http client)
2. **Aktif bakim** — Son 6 ayda commit olmayan paket secme (ozzo-validation, xlzd/gotp, bas-d/appattest → reddedildi)
3. **Guvenlik gecmisi** — CVE'ler fixli olmali (crewjam/saml v0.5.1 → fixli, eski versiyonlar → tehlikeli)
4. **Kucuk paketlerde vendor/fork** — 50 star altinda paketler (go-dpop, go-app-attest) vendor veya fork edilmeli
5. **Interface-based tasarim** — Paket degisikligi kolay olmali. Ornek: `EmailSender` interface → SMTP, SES, Console impl. Yarin baska impl eklenebilir
6. **Tek sorumluluk** — Bir is icin bir paket. go-jose (JOSE suite) + golang-jwt (basit JWT) birlikte kullanilir, biri digerini replace etmez
