# PalAuth — SDK Tasarimi

> Bu dosya PalAuth SDK'larinin tasarimini tanimlar.
> Go auth server REST API sunar. SDK'lar bu API'nin thin wrapper'lari — OpenAPI spec'ten (`api/openapi.yaml`) generate edilir.
> Core fonksiyonalite icin: [spec.md](spec.md)
> Sertifikasyon icin: [spec-compliance.md](spec-compliance.md)
> SaaS platform icin: [spec-saas.md](spec-saas.md)

---

## 1. SDK Genel Bakis

| SDK | Dil | Platform | Amac | Faz |
|-----|-----|----------|------|-----|
| `@palauth/client` | TypeScript | Next.js, React, Vue, browser | Frontend auth (login, signup, MFA, session) | Faz 0 |
| `@palauth/server` | TypeScript | NestJS, Express, Fastify | Backend token verify, admin ops, hooks | Faz 0 |
| `@palauth/edge` | TypeScript | Cloudflare Workers, Vercel Edge | JWT dogrulama (<50KB) | Faz 2 |
| `@palauth/nestjs` | TypeScript | NestJS | Decorator-based wrapper (@RequireAuth, @CurrentUser) | Faz 2 |
| `palauth-go` | Go | Go backends | Native Go SDK | Faz 0 |
| `palauth-mobile` | Kotlin (KMP) | iOS + Android | Kotlin Multiplatform — tek codebase, iki platform | Faz 2 |
| `palauth-python` | Python | Django, FastAPI, Flask | Ileride |
| `palauth-java` | Java/Kotlin | Spring Boot | Ileride |

### SDK Mimarisi

```
Go Auth Server (localhost:3000)
  |
  |-- REST API (OpenAPI spec: api/openapi.yaml)
  |
  +-- SDK'lar (thin wrapper, OpenAPI'den generate)
      |
      |-- @palauth/client (TypeScript)
      |     Browser/Next.js'te calisir
      |     pk_live_xxx ile authenticate
      |     Token persistence, auto-refresh, PKCE, onAuthStateChange
      |
      |-- @palauth/server (TypeScript)
      |     Node.js backend'de calisir
      |     sk_live_xxx ile authenticate
      |     Token verify, admin ops, blocking hooks, event listeners
      |
      |-- @palauth/edge (TypeScript)
      |     Edge runtime'da calisir
      |     Go server'a istek ATMAZ — JWT'yi lokal dogrular
      |     JWKS'i bir kere ceker, cache'ler
      |     <50KB bundle
      |
      |-- @palauth/nestjs (TypeScript)
      |     @palauth/server uzerine decorator wrapper
      |     @RequireAuth(), @CurrentUser()
      |
      |-- palauth-go (Go)
      |     Go backend'ler icin native SDK
      |     Ayni API, Go idioms ile
      |
      |-- palauth-mobile (Kotlin KMP)
            iOS + Android tek codebase
            Platform-specific: Keychain/Keystore, Biometric, Attestation
```

---

## 2. Client SDK (`@palauth/client`)

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

**Client SDK sorumluluklar:**
- PKCE code_verifier/challenge generation (OAuth flows)
- Token persistence (platform-appropriate storage)
- Automatic token refresh (background, before expiry)
- DPoP proof generation (financial-grade mode)
- Device attestation coordination
- Observable auth state (onAuthStateChange)

---

## 3. Server SDK (`@palauth/server`)

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

---

## 4. Edge SDK (`@palauth/edge`)

```typescript
import { createVerifier } from '@palauth/edge';

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

**Teknik:**
- <50KB bundle size
- Sifir runtime dependency
- JWKS caching (configurable TTL)
- `kid` bazli key secimi
- RS256, PS256, ES256, EdDSA destegi
- Web Crypto API kullanir (Node.js crypto degil)

---

## 5. KMP Mobile SDK (`palauth-mobile`)

Kotlin Multiplatform — tek codebase'den iOS ve Android SDK uretir.

```kotlin
val auth = PalAuth.create(
    url = "https://auth.myapp.com",
    apiKey = "pk_live_xxx"
)

// Login
auth.signIn(email = "user@example.com", password = "...")

// Passkey
auth.passkey.register()
auth.passkey.authenticate()

// Device attestation (platform-specific)
auth.device.attest()  // Android: Play Integrity, iOS: App Attest

// Transaction approval (PSD2 SCA)
auth.transaction.approve(
    amount = 100.0, currency = "EUR", payee = "Alice"
)

// Auth state observation
auth.onAuthStateChange { event, session -> ... }
```

**Platform-specific:**
- Android: EncryptedSharedPreferences, Android Keystore, Play Integrity API, BiometricPrompt
- iOS: Keychain, Secure Enclave, App Attest, LAContext (Face ID / Touch ID)
- Ortak: Token persistence, auto-refresh, PKCE, DPoP proof generation

---

## 6. NestJS SDK (`@palauth/nestjs`)

`@palauth/server` uzerine decorator-based wrapper. Go auth server'a istek atar.

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

## 7. SDK Design Principles

1. **Thin wrapper:** SDK'lar logic icermez, sadece Go server API'sine HTTP call yapar
2. **OpenAPI-driven:** Tum SDK'lar `api/openapi.yaml`'den generate edilir (Fern/Speakeasy)
3. **Type-safe:** Full TypeScript types, Go structs, Kotlin data classes
4. **Zero runtime deps:** Core SDK'larda sifir harici dependency
5. **Tree-shakeable:** ESM modules, kullanilmayan ozellikler bundle'a girmez
6. **Observable state:** `onAuthStateChange` tum platform'larda
7. **Auto token lifecycle:** Persistence, refresh, retry SDK tarafindan yonetilir
8. **Blocking hooks + events:** Hooks pipeline'i kontrol eder, events bilgilendirir
