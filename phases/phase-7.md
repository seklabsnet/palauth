# PalAuth — Faz 7: SaaS Platform + i18n + WCAG

> Hedef: Tum core (Faz 0-4) + SDK'lar (Faz 5) + Next-Gen (Faz 6) tamamlanmis.
> Simdi urunu SaaS olarak sun: billing, onboarding, hosting, landing page.
> i18n (coklu dil) + WCAG (erisilebilirlik) dashboard/SDK isi — Go server degil.
> Detaylar: [spec-saas.md](../spec-saas.md)

---

## T7.1 — i18n (Coklu Dil)

**Ne:** SDK'lar ve Dashboard icin coklu dil destegi. Go server machine-readable error code doner, ceviri SDK/Dashboard tarafinda.

**Yapilacaklar:**
- Client SDK: Locale dosyalari (en, tr, de, fr, es, ar, zh, ja, ko, pt)
  - Error code → human-readable ceviri mapping
  - `createAuthClient({ url, apiKey, locale: 'tr' })`
- KMP SDK: Ayni locale sistemi (shared resources)
- Dashboard (Next.js): next-intl veya benzeri i18n framework
  - Tum UI metinleri cevrili
  - RTL destegi (Arapca, Ibranice)
- Email template'leri: Project config'den dil secimi, template'ler coklu dil
- SMS icerikleri: Dil bazinda

**Kabul kriterleri:**
- [ ] SDK 10+ dil destekliyor
- [ ] Dashboard en + tr calisiyor
- [ ] RTL (Arapca) dogru render ediliyor
- [ ] Email template'ler dil bazinda calisiyor

---

## T7.2 — WCAG 2.1 AA (Erisilebilirlik)

**Ne:** Dashboard WCAG 2.1 AA uyumlu.

**Yapilacaklar:**
- ARIA labels tum interactive elementlerde
- Keyboard navigation (tab order, focus management)
- Renk kontrast (min 4.5:1)
- Screen reader destegi
- Form validation hatalari acik ve anlasilir
- Accessibility audit araci ile otomatik test

**Kabul kriterleri:**
- [ ] WCAG 2.1 AA audit geciyor
- [ ] Screen reader ile dashboard kullanilabiliyor
- [ ] Keyboard-only navigation calisiyor

---

## T7.3 — Stripe Billing Entegrasyonu

**Ne:** SaaS fiyatlandirma tier'lari, subscription + usage-based MAU billing.

**Yapilacaklar:**
- Stripe integration: subscription create/update/cancel
- Tier'lar: Free, Pro ($49/ay), Business ($249/ay), Enterprise (custom)
- MAU metering: Kullanim takibi + Stripe usage reporting
- Overage billing: Limit asimi faturalandirma
- Billing dashboard: Plan, kullanim, fatura gecmisi, odeme yontemi
- Webhook handler: Stripe event'leri (payment success/failure, subscription cancel)

**Kabul kriterleri:**
- [ ] Stripe subscription create calisiyor
- [ ] MAU metering calisiyor
- [ ] Tier upgrade/downgrade calisiyor
- [ ] Billing dashboard calisiyor

---

## T7.4 — SaaS Onboarding + Managed Hosting

**Ne:** Yeni musteri kaydi → proje olustur → quickstart.

**Yapilacaklar:**
- SaaS signup flow (ayri Next.js app):
  1. Email + sifre ile kayit (PalAuth'un kendi auth'unu kullanir — dogfooding)
  2. Proje olustur (isim + platform secimi)
  3. API key'ler gosterilir
  4. Framework-based quickstart (Next.js, React, NestJS, Go, Flutter...)
  5. Canli test: Dashboard'da login denemesi izle
- Managed hosting altyapisi:
  - Shared instance (Free/Pro): project_id ile izolasyon
  - Dedicated instance (Business/Enterprise): Kubernetes pod
  - Instance lifecycle: create, scale, monitor, delete
- Project migration (upgrade): Shared → dedicated instance'a veri tasima

**Kabul kriterleri:**
- [ ] SaaS signup → proje olustur → API key'ler → quickstart calisiyor
- [ ] Shared instance calisiyor (Free/Pro)
- [ ] Dedicated instance calisiyor (Business/Enterprise)
- [ ] Project migration calisiyor (shared → dedicated)

---

## T7.5 — Landing Page + Documentation Portal

**Ne:** Marketing site + developer docs + interactive API playground.

**Yapilacaklar:**
- Landing page (Next.js static site veya Astro):
  - Urun tanitimi
  - Fiyatlandirma tablosu
  - Rakip karsilastirma
  - Quickstart demo
- Documentation portal:
  - API reference (OpenAPI spec'ten otomatik — Redoc veya Scalar)
  - Quickstart rehberleri (framework bazli)
  - SDK referanslari
  - Compliance/sertifika bilgileri
- Interactive API playground:
  - Dashboard icinde canli API tester
  - curl komutlari projeye ozel key'ler ile dolu
  - SDK ornekleri key'ler ile dolu

**Kabul kriterleri:**
- [ ] Landing page yayinda
- [ ] Documentation portal yayinda
- [ ] API playground calisiyor
- [ ] Quickstart rehberleri tum framework'ler icin hazir

---

## Haftalik Plan (20+ hafta)

| Hafta | Task'lar | Not |
|-------|----------|-----|
| 1-3 | T7.1 (i18n — SDK + Dashboard + email template ceviri) | |
| 4-5 | T7.2 (WCAG 2.1 AA — Dashboard erisilebilirlik) | |
| 6-10 | T7.3 (Stripe billing — subscription, MAU metering, tiers) | |
| 11-15 | T7.4 (SaaS onboarding + managed hosting + instance lifecycle) | |
| 16-20 | T7.5 (Landing page + docs portal + API playground) | |
