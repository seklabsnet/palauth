# PalAuth — Faz 5: SDK'lar (KMP Mobile, TypeScript, NestJS, Edge)

> Hedef: Tum Go server API'si kararli. SDK'lar tek seferde duzgun yazilir.
> Faz 0-4 (core Go server) tamamlanmis. API degismeyecek, SDK'lar bu API uzerine.
> Oncelik: KMP Mobile > TypeScript Client > TypeScript Server/NestJS > Edge

---

## SDK Mimarisi

```
Go Auth Server (localhost:3000) — Faz 0-4'te tamamlandi
    |
    |-- REST API (OpenAPI spec: api/openapi.yaml — source of truth)
    |
    +-- SDK'lar (thin wrapper + platform-specific logic)
        |
        |-- palauth-mobile (KMP — iOS + Android)
        |-- @palauth/client (TypeScript — Next.js, React, Vue)
        |-- @palauth/server (TypeScript — NestJS, Express backend)
        |-- @palauth/nestjs (TypeScript — NestJS decorator wrapper)
        |-- @palauth/edge (TypeScript — Cloudflare Workers, Vercel Edge)
```

Client'tan gonderilen extra metadata → hook payload'da backend'e ulasir:

```
Client SDK                     Go Server                    NestJS Backend (Server SDK)
    |                              |                              |
    | auth.signIn({                |                              |
    |   email, password,           |                              |
    |   metadata: {                |                              |
    |     plan: "pro",             |                              |
    |     referral: "abc"          |                              |
    |   }                          |                              |
    | })                           |                              |
    |----------------------------->|                              |
    |                              | before.login hook            |
    |                              |----------------------------->|
    |                              | payload: {                   |
    |                              |   user, context,             |
    |                              |   client_metadata: {         |
    |                              |     plan: "pro",             |
    |                              |     referral: "abc"          |
    |                              |   }                          |
    |                              | }                            |
    |                              |                              |
    |                              |<--- { verdict: "allow",      |
    |                              |       custom_claims: {       |
    |                              |         role: "premium"      |
    |                              |       }                      |
    |                              |     }                        |
    |                              |                              |
    |<--- { access_token (role:premium), refresh_token }          |
```

---

## T5.1 — OpenAPI Spec Finalize + SDK Generation Pipeline

**Ne:** Tum Faz 0-4 endpoint'lerini kapsayan final OpenAPI spec. SDK generation altyapisi.

**Yapilacaklar:**
- `api/openapi.yaml` — Tum endpoint'ler (auth, admin, oauth, scim, webauthn, hooks, webhooks)
- `oapi-codegen` config: Go server types (zaten var) + Chi router
- SDK generation script (`make generate-sdk`):
  - TypeScript types generate (openapi-typescript)
  - Go client generate (oapi-codegen client mode)
- Spec validation: `swagger-cli validate api/openapi.yaml`
- Tum endpoint'lerin request/response schema'lari tanimli
- Error response format standardize (`ErrorResponse` struct)

**Kabul kriterleri:**
- [ ] OpenAPI spec valid
- [ ] Tum Faz 0-4 endpoint'leri spec'te
- [ ] Request/response schema'lari tanimli
- [ ] `make generate-sdk` calisiyor

**Bagimlilk:** Faz 0-4 tamamlanmis

---

## T5.2 — KMP Mobile SDK (palauth-mobile)

**Ne:** Kotlin Multiplatform — tek codebase'den iOS ve Android SDK. Birincil SDK.

**Yapilacaklar:**
- Shared code (commonMain):
  - `PalAuth.create(url, apiKey)` → client
  - Auth methods: `signIn(email, password, metadata?)`, `signUp(email, password, metadata?)`, `signOut()`
  - `signInWithOAuth(provider)` → platform browser'da OAuth redirect
  - `signInWithCredential(provider, idToken)` → native Google/Apple Sign-In token exchange
  - `signInWithPasskey()`, `registerPasskey()` → WebAuthn
  - `mfa.enroll(type)`, `mfa.challenge(mfaToken, code)`, `mfa.verify(code)`
  - `stepUp(method)` → step-up auth
  - `transaction.approve(amount, currency, payee)` → PSD2 SCA
  - `device.register()`, `device.attest()` → platform attestation
  - `recovery.generateCodes()`, `recovery.useCode(code)`
  - `getSession()`, `getUser()`, `signOut()`
  - `onAuthStateChange(callback)` → auth state observation
  - Token persistence (expect/actual pattern)
  - Token auto-refresh (background, before expiry)
  - PKCE code_verifier/challenge generation
  - DPoP proof generation (FAPI mode)
  - Client metadata gonderme (extra JSON → hook payload'a ulasir)

- Android (androidMain):
  - `EncryptedSharedPreferences` → token persistence
  - `Android Keystore` → DPoP key storage
  - `Play Integrity API` → device attestation
  - `BiometricPrompt` → biometric auth (passkey, step-up)
  - `CredentialManager` → passkey registration/authentication

- iOS (iosMain):
  - `Keychain` → token persistence
  - `Secure Enclave` → DPoP key storage
  - `App Attest` → device attestation
  - `LAContext` (Face ID / Touch ID) → biometric auth
  - `ASAuthorization` → passkey registration/authentication

**Kabul kriterleri:**
- [ ] Android: signIn/signUp calisiyor
- [ ] iOS: signIn/signUp calisiyor
- [ ] Android: Google Sign-In → signInWithCredential calisiyor
- [ ] iOS: Apple Sign-In → signInWithCredential calisiyor
- [ ] Android: Passkey registration/authentication calisiyor
- [ ] iOS: Passkey registration/authentication calisiyor
- [ ] Android: Play Integrity attestation calisiyor
- [ ] iOS: App Attest attestation calisiyor
- [ ] Android: BiometricPrompt calisiyor
- [ ] iOS: Face ID/Touch ID calisiyor
- [ ] Token auto-refresh calisiyor (background)
- [ ] onAuthStateChange calisiyor
- [ ] Client metadata → hook payload'a ulasir
- [ ] DPoP proof generation calisiyor (FAPI mode)
- [ ] Transaction approve calisiyor (PSD2 SCA)
- [ ] MFA flow calisiyor (TOTP + SMS + Email OTP)

**Bagimlilk:** T5.1 (OpenAPI spec)

---

## T5.3 — TypeScript Client SDK (@palauth/client)

**Ne:** Next.js, React, Vue frontend'ler icin TypeScript client SDK.

**Yapilacaklar:**
- `sdk/typescript/client/`:
  - `createAuthClient({ url, apiKey })` → client instance
  - Auth: `signUp()`, `signIn()`, `signOut()`, `signInWithOAuth()`, `signInWithCredential()`, `signInWithMagicLink()`, `signInWithPasskey()`, `registerPasskey()`
  - MFA: `mfa.enroll()`, `mfa.verify()`, `mfa.challenge()`
  - Step-up: `stepUp({ method })`
  - Transaction: `transaction.approve({ amount, currency, payee })`
  - Device: `device.register()`, `device.attest()`
  - Recovery: `recovery.generateCodes()`, `recovery.useCode()`
  - Session: `getSession()`, `getUser()`, `getAccessToken()`
  - State: `onAuthStateChange(callback)` — reactive
  - Token lifecycle: auto-persistence (localStorage/sessionStorage/cookie/memory), auto-refresh
  - PKCE generation
  - DPoP proof generation (FAPI mode)
  - **Client metadata**: `signIn({ email, password, metadata: { plan: "pro" } })` → metadata hook payload'da
  - Tree-shakeable ESM
  - Zero runtime dependency
  - npm: `@palauth/client`

**Kabul kriterleri:**
- [ ] `createAuthClient()` calisiyor
- [ ] signIn/signUp/signOut calisiyor
- [ ] Social login (OAuth redirect + callback) calisiyor
- [ ] Passkey registration/authentication calisiyor
- [ ] MFA flow calisiyor
- [ ] Token auto-refresh calisiyor
- [ ] onAuthStateChange calisiyor
- [ ] Client metadata hook'a ulasir
- [ ] Tree-shakeable (<20KB core bundle)
- [ ] Next.js + React + Vue ile calisiyor

**Bagimlilk:** T5.1 (OpenAPI spec)

---

## T5.4 — TypeScript Server SDK (@palauth/server)

**Ne:** NestJS, Express, Fastify backend'ler icin TypeScript server SDK. Hook handler.

**Yapilacaklar:**
- `sdk/typescript/server/`:
  - `createAuthServer({ url, serviceKey })` → server instance
  - Token: `verifyToken(jwt)` → decoded claims
  - Admin: `admin.createUser()`, `updateUser()`, `deleteUser()`, `listUsers()`, `banUser()`, `setCustomClaims()`, `revokeAllSessions()`, `createCustomToken()`, `impersonate()`
  - Orgs: `orgs.create()`, `orgs.addMember()`, `orgs.configureSso()`
  - **Blocking hooks**:
    ```typescript
    auth.hooks.before('user.create', async (event) => {
      // event.user, event.context, event.client_metadata
      const user = await db.users.create({ authId: event.user.id, plan: event.client_metadata.plan });
      return { allow: true, metadata: { dbUserId: user.id }, custom_claims: { role: "premium" } };
    });
    ```
  - Hook HMAC dogrulama (incoming webhook'larin gercek PalAuth'tan geldigini dogrula)
  - **Non-blocking events**:
    ```typescript
    auth.on('user.created', async (event) => {
      await crm.createContact(event.user);
    });
    ```
  - npm: `@palauth/server`

**Kabul kriterleri:**
- [ ] `createAuthServer()` calisiyor
- [ ] `verifyToken()` calisiyor (JWT dogrulama)
- [ ] Admin CRUD calisiyor
- [ ] Blocking hook handler calisiyor (before.user.create, before.login, vb.)
- [ ] Hook HMAC dogrulama calisiyor (sahte webhook reject)
- [ ] Event listener calisiyor (user.created, login.failed, vb.)
- [ ] Client metadata hook event'te erisilebiliyor (`event.client_metadata`)

**Bagimlilk:** T5.1 (OpenAPI spec)

---

## T5.5 — NestJS SDK (@palauth/nestjs)

**Ne:** NestJS backend'ler icin decorator-based wrapper. `@palauth/server` uzerine.

**Yapilacaklar:**
- `sdk/typescript/nestjs/`:
  - `AuthServerModule.register({ url, serviceKey, hooks })` — NestJS module
  - `@RequireAuth()` — guard decorator (AAL1 yeterli)
  - `@RequireAuth({ acr: 'aal2', mfa: true })` — step-up zorunlu
  - `@RequireAuth({ acr: 'aal3', dpop: true })` — hardware key + DPoP zorunlu
  - `@CurrentUser()` — param decorator → AuthUser object
  - Hook handler interface:
    ```typescript
    @Injectable()
    export class BeforeUserCreateHandler implements AuthHookHandler {
      async handle(event: AuthHookEvent): Promise<AuthHookResponse> {
        // event.user, event.context, event.client_metadata
        return { allow: true, metadata: { dbUserId: user.id } };
      }
    }
    ```
  - npm: `@palauth/nestjs`

**Kabul kriterleri:**
- [ ] `AuthServerModule.register()` calisiyor
- [ ] `@RequireAuth()` guard calisiyor (valid token → pass, invalid → 401)
- [ ] `@RequireAuth({ acr: 'aal2' })` step-up kontrol calisiyor
- [ ] `@CurrentUser()` dogru user donuyor
- [ ] Hook handler interface calisiyor (NestJS DI ile)
- [ ] Client metadata hook event'te erisilebiliyor

**Bagimlilk:** T5.4 (Server SDK)

---

## T5.6 — Edge SDK (@palauth/edge)

**Ne:** Cloudflare Workers, Vercel Edge'de JWT dogrulama. <50KB. Network round-trip yok.

**Yapilacaklar:**
- `sdk/typescript/edge/`:
  - `createVerifier({ jwksUrl, issuer, audience })` → verifier
  - `verifier.verify(token)` → `{ valid, claims, error }`
  - `verifier.verifyDPoP(proof, token, request)` → DPoP dogrulama
  - `verifier.checkAcr(claims, requiredAcr)` → ACR kontrol
  - JWKS caching (configurable TTL)
  - Web Crypto API (Node.js crypto degil)
  - <50KB bundle, zero dependency
  - npm: `@palauth/edge`

**Kabul kriterleri:**
- [ ] JWT dogrulama calisiyor (Cloudflare Workers'da)
- [ ] JWT dogrulama calisiyor (Vercel Edge'de)
- [ ] JWKS caching calisiyor
- [ ] DPoP dogrulama calisiyor
- [ ] ACR kontrol calisiyor
- [ ] <50KB bundle size
- [ ] Zero external dependency

**Bagimlilk:** T5.1 (OpenAPI spec, JWKS endpoint)

---

## T5.7 — SDK Test Sweep

**Ne:** Tum SDK'lar icin integration + contract testleri.

**Yapilacaklar:**
- Contract tests (Pact):
  - Client SDK ↔ Go Server API uyumu
  - Server SDK ↔ Go Server Admin API uyumu
  - NestJS SDK ↔ Go Server hook/webhook uyumu
- Integration tests:
  - KMP: Android emulator + iOS simulator ile full flow
  - Client SDK: Playwright ile browser-based OAuth flow
  - Server SDK: Hook handler end-to-end (Go server → hook → NestJS → response)
  - Edge SDK: Miniflare (Cloudflare Workers test env) ile JWT verify
  - Client metadata flow: Client SDK gonder → Go server → hook → Server SDK al → response → Client SDK al
- Cross-SDK consistency:
  - Tum SDK'lar ayni API'yi ayni sekilde cagiriyor mu
  - Error handling tutarli mi
  - Token refresh logic tutarli mi

**Kabul kriterleri:**
- [ ] Pact contract testler geciyor (tum SDK'lar)
- [ ] KMP Android + iOS integration geciyor
- [ ] Client metadata end-to-end flow calisiyor
- [ ] Edge SDK Miniflare'da calisiyor
- [ ] Hook handler end-to-end calisiyor
- [ ] Tum SDK'lar ayni error format'i handle ediyor

**Bagimlilk:** T5.2-T5.6

---

## Haftalik Plan (16 hafta)

| Hafta | Task'lar | Not |
|-------|----------|-----|
| 1-2 | T5.1 (OpenAPI spec finalize + generation pipeline) | Altyapi |
| 3-6 | T5.2 (KMP Mobile SDK — Android + iOS) | En buyuk SDK |
| 7-9 | T5.3 (TypeScript Client SDK) | Frontend |
| 10-12 | T5.4 (TypeScript Server SDK) + T5.5 (NestJS SDK) | Backend |
| 13-14 | T5.6 (Edge SDK) | Edge runtime |
| 15-16 | T5.7 (SDK test sweep — Pact, integration, cross-SDK) | Final |
