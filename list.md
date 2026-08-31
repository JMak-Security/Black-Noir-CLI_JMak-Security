# Black Noir CLI — API Key Buying Priority

Goal: maximize performance without wasting money. Ranked by value-for-money,
grounded in the keys the tool actually reads (`.env.example` / `blacknoir/`).
Prices drift — verify at signup; the ranking holds regardless.

---

## Tier 0 — Do this now (FREE, no wallet)

Free registrations the tool already supports. Gets you ~70–80% of the ceiling
for $0. Do this before spending a cent.

- [ ] **GITHUB_TOKEN** — GitHub code search. Free forever (personal access
  token, no scopes needed). Handle→identity + leaked-secret pivots.
- [ ] **An LLM key (Groq OR Google AI Studio)** — the agent's planning/synthesis
  brain. Free tier. Better model = better queries, less noise.
- [ ] **INTELX_API_KEY** — Intelligence X leak/paste/darknet index. Free dev key
  (~50 searches). Best *free* dark-web index. Get 2–3 keys, comma-separate them
  for auto-failover.
- [ ] **SERPER_API_KEY (signup credits)** — Google SERP, the workhorse engine.
  ~2,500 free queries on signup. Everything downstream feeds off web recall.
- [x] **XposedOrNot** — keyless email breach check. Already wired in, no key.
- [ ] **NUMVERIFY / SAUCENAO free tiers** — phone carrier / reverse-image. Only
  if you actually search phones or feed images.

---

## Tier 1 — Buy first when you have income

**1. SERPER (paid) — ~$50, pay-as-you-go.**
Best money you can spend. Pay-per-use, credits never expire, NO subscription —
can't bankrupt you; top up when you run dry. The engine everything depends on.

**2. HIBP_API_KEY — ~$4.50/month.**
Gold-standard breach signal, dirt cheap. The one thing XposedOrNot can't fully
replace (bigger corpus, per-account email lookups). Pause any month you're idle.

> Two keys total for a maxed person/leak setup: one ~$50 top-up you control,
> one ~$4.50/mo you can cancel anytime.

---

## Tier 2 — Situational (only if your targets need it)

- **SHODAN_API_KEY** — one-time membership (~$49, but drops to ~$1–5 on Black
  Friday — WAIT for the sale). Only for IP / domain / infrastructure targets.
  Useless for people or leaks.
- **INTELX paid** — pricey (hundreds/yr). Only if you exhaust free keys on
  serious leak work.
- **NUMVERIFY paid** — only for heavy phone-number work; free tier + keyless
  `phone.py` analyzer already cover most of it.

---

## Don't waste money on

- **DEHASHED_API_KEY** — connector is DISABLED in the registry (removed).
  Buying it does nothing right now. Ask to re-enable `_run_dehashed` first if you
  ever want it (~$180/yr, powerful but overkill for a hobby budget).
- **Messaging keys** (EMAIL, TELEGRAM, META, YOUTUBE) — power the outreach/
  messenger feature, NOT OSINT search. Irrelevant to investigation performance.

---

## Services with NO free/public API (can't be added)

Requested but not connectable — no self-serve key exists for any of them:

- **National Public Data** — defunct breached broker; a data source, not a service.
- **Experian Dark Web Scan** — consumer web form; real APIs are enterprise,
  paid-contract only.
- **DeXpose** — B2B, sales/demo-gated.
- **Aura** — consumer subscription app; no public API.

Replaced by **XposedOrNot** (free, keyless), which delivers the same
"is my stuff leaked" value.

---

## Summary

| When | Spend | Result |
|---|---|---|
| Today | $0 | GitHub + free LLM + free IntelX + Serper free credits + XposedOrNot → ~70–80% of ceiling |
| First paycheck | ~$50 once + ~$4.50/mo | Serper paid + HIBP → maxed for person/leak work |
| If infra-hunting | ~$1–49 (on sale) | Shodan |
| Never (for now) | — | DeHashed (disabled), messaging keys (wrong feature) |
