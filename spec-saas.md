# PalAuth — SaaS Platform Spec (Ileride Detaylanacak)

> Bu dosya PalAuth'un SaaS katmanini tanimlar. **Faz 4+'te** detaylandirilacak.
> Self-hosted birincil deployment. SaaS, core Go server'in uzerine bir orchestration layer.
> Core fonksiyonalite icin: [spec.md](spec.md)
> Sertifikasyon icin: [spec-compliance.md](spec-compliance.md)
> SDK'lar icin: [spec-sdk.md](spec-sdk.md)

---

## 1. Mimari

```
SaaS Platform (Next.js — ayri repo, kapali kaynak)
  |
  |-- Kendi DB'si (musteriler, billing, planlar)
  |     - customers: tenant_id, email, plan, stripe_id, assigned_instance, project_ids[]
  |     - instances: instance_id, url, region, tier, health
  |
  |-- PalAuth Go Server Admin API'sini kullanir
  |     - Project olustur/sil
  |     - API key yonet
  |     - Kullanici/session verilerine erismez
  |
  |-- Stripe billing (subscription + MAU usage-based)
  |
  |-- Instance orchestration (Kubernetes)
        - Free/Pro: Shared instance (project_id ile izolasyon)
        - Business: Dedicated instance
        - Enterprise: Dedicated instance + dedicated DB
```

**Go server SaaS'tan habersiz.** Kimin ne odedigini, hangi planda oldugunu bilmiyor. Sadece project bazinda auth isi yapiyor.

---

## 2. Detaylanacak Konular

- [ ] Fiyatlandirma tier'lari (Free/Pro/Business/Enterprise)
- [ ] Stripe entegrasyonu
- [ ] Shared vs dedicated instance yonetimi
- [ ] Musteri onboarding akisi
- [ ] MAU metering + kullanim limitleri
- [ ] Project migration (shared -> dedicated, upgrade sirasinda)
- [ ] Landing page / marketing site
- [ ] Open core vs full open source karari
- [ ] Self-hosted enterprise lisans modeli
- [ ] Migration araclari (Auth0, Firebase, Supabase, Clerk import)
