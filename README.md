<p align="center">
  <img src="assets/BlackNoirLogo.png" alt="Black Noir CLI" width="160">
</p>

# Black Noir CLI — Deep-Search OSINT AI Agent

> ### ⚠️ Disclaimer — independent personal project
>
> **Black Noir CLI is an independent, personal, non-commercial project.**
>
> It is **not affiliated with, endorsed by, sponsored by, or connected to**
> Sony Pictures Entertainment, Amazon Studios, Prime Video, Dynamite
> Entertainment, or the creators, owners or rights-holders of *The Boys* — the
> comic series or any of its television adaptations. It has **no relationship**
> to the fictional character of the same name, or to any character, storyline,
> trademark or property from that franchise.
>
> The name is used only as a project codename, chosen for its plain-English
> meaning ("black" + *noir*, as in noir detective fiction — the tool does
> deep-search investigative work). Any resemblance to the franchise is
> coincidental and unintended. All trademarks referenced remain the property of
> their respective owners.
>
> This project is not a product, service or publication of the author's
> employer, school, or any organisation the author is affiliated with. It is
> released as-is, with no warranty, for research and educational use.

A visual, reasoning OSINT agent. Give it a name, a handle, an email, a domain,
a photo, or a plain-English instruction — it plans an investigation, searches
two surfaces, reverse-searches images, correlates every identifier into an
interactive link graph, and writes a self-contained HTML report. It also has an
interactive **chat mode** for open questions.

> **Safety first.** Black Noir reads **search-index metadata only**. It **never**
> connects to a `.onion` service, **never** downloads a file, and **never**
> follows a result link. Every network decision is allow-listed and logged. It is
> for **authorized** OSINT / research on **public** information.

---

## Scope — what's effective, what's not

Black Noir is a **multi-key aggregator**: it's only as strong as the *identifier*
you feed it. Different inputs unlock different modules, and they are **not**
equally effective. A person's **name** is the weakest key it accepts; the
machine-readable identifiers that indexes actually file data under are the strong
ones.

Each row shows an **example you'd type in `--chat`** (natural phrasing works;
`/search …` forces an investigation). The type is auto-detected from the input.

| Input key | Example chat prompt | Modules it activates | Effectiveness |
|-----------|---------------------|----------------------|---------------|
| **email** | `search john.doe@example.com` | HIBP per-account, IntelX, DeHashed | 💪 strong — *is this account breached?* |
| **domain** | `search example.com` | RDAP/WHOIS, crt.sh (CT logs), passive DNS, hostsearch, Wayback | 💪 strong — org's external attack surface |
| **IP address** | `investigate 203.0.113.10` | Shodan InternetDB / full, reverse-IP, passive DNS | 💪 strong — open ports, services, CVEs |
| **username / @handle** | `investigate @nightowl` | 22-site cross-platform sweep, GitHub/Reddit/Bluesky/Mastodon | 👍 good pivot — where the handle exists |
| **BTC address** | `search 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` | Blockstream | 👍 good — balance, tx count, activity |
| **phone number** | `search +852 5550 0103` | Numverify (keyed), web/social, runbook HLR/scam-DB pivots | ⚖️ moderate — carrier/region + public mentions |
| **company / org** | `investigate Acme Corp` | web/news search, LinkedIn, domain pivots (→ feed the domain) | ⚖️ moderate — a *discovery* key for its domains/people |
| **onion address** | `search <hash>.onion` | clearnet dark-web *indexes* only (Ahmia/Lyzem) — **never fetched** | ⚖️ index-only — kept as text, opened manually in Tor |
| **image / photo** | drop file in `input/`, then `who is this` | SauceNAO/IQDB (art), Yandex/Lens links (person), EXIF/GPS, vision | ⚖️ varies — art = strong, person = consent-gated links |
| **person name** | `who is Ada Lovelace` | web search + social scraping only | 🥱 **weak & noisy** — *discovery only* |
| **free-form instruction** | `This is Jensen Huang, find every public detail` | parsed into `{subject, type, depth}`, then routed as above | ➡️ as strong as the *key it resolves to* |

### Discovery keys vs. depth keys

- A **name is a discovery key.** Use it to *find* strong identifiers — an email,
  a handle, a domain the subject owns — then **pivot** to those for depth.
- Feed a name and expect a deep result, and you activate only the weakest slice
  of the tool. The infra / breach / dark-web modules **skip themselves** because
  they have nothing to key on — you'll see `needs a domain/IP target` and
  `per-account lookup needs HIBP_API_KEY` in the log. Those aren't failures;
  they're modules correctly declining a key they can't use.

### Reading a "nothing found" result

An empty result is **not** proof of no exposure — it's a statement about *that
engine's index and key*:

- **Dark-web engines (Ahmia, Lyzem, IntelX-free)** index by *keyword / email /
  username*, are shallow (opt-in onion sites, Telegram, metadata-only), and skew
  English. A **name** query — especially a non-Latin one — will almost always
  come back empty even when real exposure exists elsewhere. Empty here = "these
  shallow, name-indexed engines didn't surface it," nothing more.
- **The authoritative breach signal is email-keyed** and lives in **HIBP**. A
  name query never reaches it. If you want a real answer to "am I leaked?", run
  the **email** through HIBP — that's the one check that actually lights up.
- **Web + social scraping (the name path)** is the *noisiest* surface: lots of
  namesakes, and correlation, not depth, is what it's doing.

### Rule of thumb

Point Black Noir at a **domain, IP, email, or handle** and it's a capable recon
tool. Point it at a bare **person name** and you're using its weakest mode — good
for *finding* the strong keys, poor for anything deeper. Narrow to the smallest
key that answers your question: breach exposure → **email**; attack surface →
**domain**; account mapping → **handle**.

### Effective ≠ acceptable — scope by consent

The strong keys above are also where the ethics tighten. Effectiveness tells you
*what will work*; consent and data-ownership tell you *what you should point it
at*. Scope every person-directed run by **who the data belongs to** and **who
authorized the look**:

| | Green — go | Yellow — explicit consent first | Red — don't |
|---|---|---|---|
| **Org / infra** | your own or an engagement-scoped domain/IP/company | a third-party org with no scope/authorization | — |
| **Self-check** | *you* checking *your own* emails/handles for exposure | a colleague's exposure *at their request* | — |
| **Person** | — | a named individual who has **explicitly asked** you to check *their* exposure | building a background / "secrets" dossier; anything touching **family or minors** |

- **Breach self-checks belong to the account owner.** If someone wants to know
  whether *their* email is leaked, the clean path is for **them** to run it on
  **their own** address — HIBP by email needs no name and no dossier. Hand them
  the account-scoped check rather than proxying a private-life search because
  they asked.
- **Name-based sweeps pull in collateral.** Correlating a personal name against
  social scrapes is how you end up surfacing a subject's partner, children, and
  home life — people who consented to nothing. That's the failure mode the Red
  column exists to prevent, regardless of who asked.
- **Narrowest key wins here too.** "Is my account exposed?" → email. "What's my
  org's attack surface?" → domain. Neither needs a person's name or background.

See **Safety model** below for the guardrails that hard-enforce these limits.

---

## Highlights

- **Two surfaces** — Public (Bing, Google-via-Serper) + Dark-web indexes over
  clearnet (Ahmia, Lyzem, keyless-HIBP for domains) plus manual/Tor-only
  Torch, Telepathy, dark-web-scraper. (Bot-blocked scrapers and paid-only
  DeHashed were removed.)
- **Natural-language targets** — `"This is Jensen Huang, find every public detail"`
  is parsed into subject **Jensen Huang**, type **person**, depth **deep**.
- **Multi-engine, multi-query** — the AI writes several query angles and every
  engine sweeps them all; results are merged + deduplicated.
- **Detective read + agentic crawl** (`/read`, or paste a URL) — goes past
  snippets: fetches and **reads full pages**, extracts facts grounded in the
  text next to the name, auto-discovers an institution's site (sitemap +
  homepage + Wayback) and **navigates it link-by-link** toward the target — a
  read-only agent loop that reaches obscure pages search ranking buries.
- **Reads over snippets = fewer false findings** — a name-gate (only pages that
  name the person become evidence) + snippet-splice grounding (a fact must sit
  beside the name, not across a `…`) stop the classic "the snippet stitched two
  people together" error. Adaptive, symmetric constraints — no hardcoded
  "student vs professional" personas.
- **Honest under failure** — a run that couldn't reach any language model falls
  back to a deterministic summary and shows a red **⚠ AI DEGRADED** banner, so a
  thin result is never mistaken for "nothing exists".
- **Reverse-image search** — real uploads to **SauceNAO** + **IQDB**, routed by
  what the image *is*: art → art matchers; **person → face-appropriate engines**
  (Yandex/Lens + PimEyes/FaceCheck as manual, consent-gated links).
- **Vision** — reads signatures/handles/watermarks from images into the graph.
- **Five LLM providers** — Anthropic, OpenAI, Google, NVIDIA, local Ollama
  (auto-started). Deterministic heuristic fallback when none is set.
- **Chat mode** — `--chat` for open Q&A + `/search` commands, plus `/fetch <url>`
  to read one page you name (as text; it lists the links it finds and follows
  none).
- **Reflection loop** — after a sweep, the loop checks whether anything actually
  ties the *name* to the *context*. If not, a model panel diagnoses the miss
  (`namesakes` / `context_only` / `off_topic` / `absent`) and re-queries against
  that diagnosis. It also re-derives queries from the domains the results
  themselves revealed, with no model at all.
- **Name↔handle confirmation** — links a real name to an account handle only
  when the account **publicly declares that name** (`github.com/amarsh-sec`
  says "Alex Marsh"). A same-handle stranger is reported as explicitly *not*
  linked, never as a finding.
- **Keyless phone structure** — country, line type and *"carrier not
  determinable"* straight from the numbering plan. No key, no network, and it
  never claims to name a subscriber.
- **Self-audit** — `--check-password` checks one of your own passwords against
  Have I Been Pwned using k-anonymity; only 5 characters of the SHA-1 hash
  leave the machine.
- **Defensive preflight** — checks/starts Docker + VPN before a live search.
- **Visual report** — interactive force-directed entity graph, findings,
  timeline, guardrail audit — one self-contained HTML file. Identity candidates
  are shown **below** the engines and marked `derived`, because they are
  conclusions drawn from those engines, not sources of their own.

---

## Install

```bash
pip install -r requirements.txt      # requests, beautifulsoup4, anthropic, openai
cp .env.example .env                 # then fill in the key(s) you use
```

Everything is optional and degrades gracefully:
- no `requests`/`bs4` → **plan-only** (prepares queries, no network)
- no LLM provider / `--no-llm` → deterministic **heuristic** agent (fully offline)

Windows one-liners: `build.bat` (build the exe), `test.bat` (run tests),
`run.bat …` (run exe or fall back to source).

---

## Usage

```bash
# natural-language target + photo in input/, full live sweep
python main.py "This is Jensen Huang, search every public detail about him" --live

# a username on the dark-web surface
python main.py "@nightowl" --surface darkweb --live

# an email, everything
python main.py "john.doe@example.com" --surface all --live

# interactive chatbot
python main.py --chat

# just the checks
python main.py --doctor
python main.py --list-sources
```

### Flags

| Flag | Meaning |
|------|---------|
| `target` | a name, username, `@handle`, email, domain, phone, **or a free-form instruction** |
| `--surface public\|darkweb\|all` | which surface(s) to search (default `all`) |
| `--live` | perform real clearnet requests (default: **plan-only**, no network) |
| `--chat` | open the interactive chatbot (open Q&A + `/search`) |
| `--provider auto\|anthropic\|openai\|google\|nvidia\|ollama` | LLM backend |
| `--model id` | override the model for the chosen provider |
| `--no-llm` | force the deterministic heuristic agent |
| `--reverse-image auto\|off` | reverse-image search on input images (default auto) |
| `--enrich auto\|off` | native enrichment of domains/IPs/BTC/handles via keyless official APIs (default auto, live-only) |
| `--preflight off\|warn\|enforce` | Docker+VPN check before a live search |
| `--yes` / `-y` | auto-approve preflight install/start/spin-up |
| `--doctor` | run the Docker+VPN checks and exit |
| `--only k1,k2` | restrict to specific source keys |
| `--all-sources` | query **every** applicable source, not just the planner's pick |
| `--no-pdf` | skip the PDF report (PDF is written by default) |
| `--no-runbook` | skip the manual runbook (Tor/Telepathy steps, written by default) |
| `--input-dir` / `--output-dir` | override folders (default `input/`, `output/`) |
| `--quiet` | suppress progress output |
| `--list-sources` | list every source + provider and exit |
| `--check-password` | **self-audit:** check ONE of your own passwords against the HIBP breach corpus and exit. Prompts without echo; k-anonymity means only the first 5 characters of the SHA-1 hash are sent. Needs `--live` |

---

## Chat mode

```
python main.py --chat
```

Type open questions (answered by the LLM, with the latest findings in context)
or run investigations. In-chat commands:

```
/search <instruction>     run an investigation with current settings
/live on|off              toggle real network requests
/surface public|darkweb|all
/provider <name>          switch LLM backend
/model <id>               override model
/deep on|off              force comprehensive queries
/reverse on|off           reverse-image on input images
/candidates               list same-name candidates + their hard-constraint fit
/focus <n>                select candidate <n> → deep-dive ONLY that person
/refine <detail>          add what you know; re-narrows the candidate list
/fetch <url>              read ONE page you name, as text (needs /live on).
                          Lists the links it contains but follows none.
                          Aliases: /crawl, /read
/sources                  list all sources
/last                     show the last report path
/settings /clear /help /exit
```

Natural phrasing works too — `who is ada lovelace`, `investigate @user`,
`search example.com` are recognized as searches; anything else is a question.

---

## The agent loop

```
input/  ─▶ parse ─▶ plan ─▶ collect ─▶ reverse-image ─▶ correlate ─▶ enrich ─▶ synthesize ─▶ report
(vision   (subject  (pick    (multi-     (SauceNAO/IQDB   (entity +     (analyst      (interactive
 + text)   & depth)  engines) query)      or face links)   link graph)   summary)      HTML)
```

1. **Input folder** — text/CSV/JSON mined for identifiers; **images read with
   vision** into structured identifiers (handles, watermarks, names) that go
   straight into the graph; each image also classified (person/artwork/…).
2. **Parse** — a free-form instruction becomes `{subject, type, depth}`.
3. **Plan** — choose sources and write query angles (deeper for "everything").
   A **deep** search (or `--all-sources`) enlists *every* applicable source for
   the chosen surfaces — the whole dark-web toolset, not just the planner's pick.
4. **Collect** — each engine sweeps the full query set; merge + dedup.
5. **Reflect** — the loop reads what came back and asks whether *any* result
   ties the **name** to the **context**. Not "did we get results" and not "did
   anything name the target" (for a common name, a namesake always does) — both
   of those call a failed sweep a success. If nothing qualifies, the panel
   diagnoses the failure and re-queries; the model-free path meanwhile turns the
   domains the results revealed into `site:<their-org> "<name>"`. Reflection
   stays silent when the sweep already found the person.
6. **Reverse-image** — routed by image type (below).
7. **Correlate** — build the identifier link graph.
8. **Enrich + confirm** — keyless APIs for domains/IPs/BTC/handles/phones, then
   **name↔handle confirmation** (below).
9. **Synthesize** — analyst summary, confidence, pivots, next steps.
10. **Report** — `output/report_<subject>_<time>.html` + `.json` + **`.pdf`**
   (interactive graph in HTML; printable summary in PDF).

**Query balance.** Recon does *not* append the context to every query. An alias
goes out **alone** first: appending the org to everything hands the engine two
subjects and it ranks the one with thousands of pages, so a sweep comes back
about the school and never the pupil. A native-script name is unique enough not
to need the org. The recon row reports the split — *"61 results — 12 about the
person, 8 about the context only"* — so an org-dominated haul is a stated number
rather than something you have to notice.

**No silent rewriting.** If the panel thinks your context is misspelled, it must
report `context_mismatch` and the loop raises it as a **question**. It never
substitutes its own version into the queries: the model may be wrong, and a
query quietly retargeted at a different subject searches for the wrong person
without anyone noticing.

---

## Detective read & agentic crawl (`/read`, or paste a URL)

Search engines rank by popularity, so an obscure person's one real page loses to
their famous namesakes — and snippets *splice* non-adjacent lines, which is where
false findings come from. These read the actual pages instead. All are
**read-only** (fetch + read public pages), opt-in, and universal (the model
reasons about any site and any persona — no hardcoded domains or categories).

- **`/read`** — reads every found page that names the target, **auto-discovers**
  the institution in the context, resolves its domain (catching initialisms like
  `sbc` = St Brendon College), **merges its sitemap + homepage links +
  Wayback index**, and reads them — extracting facts grounded in the text next to
  the name. Results land in a *Detective read* report section.
- **Paste a URL / `/read <url>` / `/crawl <url>`** — a **read-only agentic
  crawl** from that page: read it → the model reasons which links lead toward the
  target → follow them → repeat, bounded by a step budget. Paste a deep page and
  it walks to related pages; paste the homepage and it navigates *into* the site.

The loop shape mirrors an autonomous operator (observe → reason → next step →
stop at budget), but the **only action is "fetch and read a public page"** — no
forms, no login, no code, nothing non-public. Reading full pages also *removes*
the snippet-splice class of error at the root. See cookbook §16.

---

## Person investigations — the phased, human-gated workflow

For a **person** target, the loop runs as five ordered phases and **hands you the
decision** before it does any deep research on an individual. Nothing about a
specific person is auto-pursued.

1. **Analyse input & extract hard constraints.** Raw input is classified into
   typed entities (name, phone, handle, …) and the qualifier you supply (e.g.
   *"student at Ko Lui Secondary School, secondary level — not university"*)
   becomes a **hard constraint** carried through every later step. A short
   pre-search summary prints before any query runs.
2. **Generate targeted queries.** Every query is **context-bound** — name + school
   + identifier variants. With a constraint supplied, the planner emits **no bare
   name-only queries** (those just pull same-name university/overseas namesakes).
   The full query set is printed before dispatch.
3. **Collect.** Queries run across the public and dark-web index sources; each
   engine's success / block / skip is logged with its reason, and raw
   snippets/URLs are preserved.
4. **Cluster & constraint-check (multi-agent).** Results become identity
   candidates. Each is tagged for **constraint fit** —
   `supports` (evidence names this person *and* fits the constraint) ·
   `unverified` (context matched but no evidence names them) ·
   `contradicts` (a university/PhD/overseas namesake) · `unknown`.
   Distinct people stay **separate candidates**; a namesake is **never** given the
   target's school/context tag without direct evidence, and different individuals
   are never merged.
5. **You select — then it goes deep.** The loop **stops** and presents every
   candidate with its match score, constraint fit, and supporting/contradicting
   evidence. Use **`/candidates`** to review and **`/focus <n>`** to pick. Only
   then does it run focused research on **that one candidate**, ruling the rest
   out as namesakes. (`/refine <detail>` re-narrows the list without committing.)

Limitations are always reported (which sources were skipped/blocked and why), and
for a subject with no public footprint the report says so plainly rather than
padding with their organisation's pages. This gate is the default for person
targets; infra targets (domain/IP/company) run straight through without it.

---

## LLM providers

Four of five speak the OpenAI wire format, so one backend serves them via
`base_url`. Selection: `--provider`, `BLACKNOIR_PROVIDER`, or auto-detect in
order `anthropic → openai → google → nvidia → ollama`.

| Provider | Auth | Vision | Notes |
|----------|------|--------|-------|
| `anthropic` | `ANTHROPIC_API_KEY` | ✅ | Claude |
| `openai` | `OPENAI_API_KEY` | ✅ | GPT-4o family |
| `google` | `GOOGLE_API_KEY` | ✅ | Gemini — **geo-blocked in HK** (`400 location not supported`); retired fast on that error |
| `nvidia` | `NVIDIA_API_KEY` | text | NIM (Nemotron etc.) |
| `ollama` | none | model-dep. | local, **auto-starts** `ollama serve` |

A run that couldn't reach any model falls back to a deterministic summary and
the report shows a red **⚠ AI DEGRADED** banner, so a thin result is never
mistaken for "nothing exists".

---

## Reverse-image search ("who drew this?" / "who is this?")

Routed by what each input image actually **is**:

| Image is… | Engines used |
|-----------|--------------|
| **artwork / logo** | **SauceNAO** + **IQDB** (real uploads → source site, creator, similarity) + general links |
| **person / scene** | **Yandex / Google Lens / Bing / TinEye** (general, face-capable) + **PimEyes / FaceCheck** (manual, **authorization/consent required**). Art matchers are skipped. |
| document / other | general links + SauceNAO |

- Real uploads (SauceNAO/IQDB) happen **only in `--live`**, to allow-listed hosts
  only, and are written to the guardrail audit log. Plan-only uploads nothing.
- Face-recognition engines are **manual links only** — never auto-uploaded — and
  are clearly labelled for authorized/consented use.
- `SAUCENAO_API_KEY` makes SauceNAO reliable (free key; keyless is throttled).

---

## Native enrichment (domains · IPs · BTC · handles)

When a run surfaces a **domain, IP, BTC address, or username** — as the target
*or* as a correlated entity — Black Noir doesn't just hand you a runbook link; it
queries the relevant **keyless official API** and folds the structured result
straight into the link graph. Runs after the first correlation pass, live-only,
JSON reads only (never a file download), onion never touched.

| Entity | Source(s) | What you get |
|--------|-----------|--------------|
| **domain** | crt.sh · Google DNS-over-HTTPS · Wayback | subdomains (from CT logs), MX/NS/TXT records, latest archive snapshot |
| **ip** | Shodan **InternetDB** (keyless) *+ Shodan full if `SHODAN_API_KEY`* | open ports, CPEs, hostnames, CVEs (+ org/OS/products with a key) |
| **btc** | Blockstream | balance, total received, tx count |
| **username** | GitHub · Reddit · **Bluesky** · **Mastodon** | account presence + profile metadata (repos, karma, followers, bio) |
| **phone** | **numbering plan (keyless, offline)** *+ Numverify if `NUMVERIFY_API_KEY`* | country, line type, and an explicit *"carrier not determinable"* where portability makes it so |

### Phone structure — what the digits alone say

Runs with **no key and no network**, so a phone target stops producing a blank
enrichment section when `NUMVERIFY_API_KEY` is absent:

```
+852 5550 0100 — Hong Kong · mobile · carrier not determinable
· Hong Kong has no area codes — the leading digit is the service block, not a
  location, so the number reveals nothing about where the holder lives.
· Carrier CANNOT be inferred: full mobile number portability since 1999.
· No public subscriber directory exists for HK mobiles, so no legitimate source
  names the holder. Any site claiming to is a data broker guessing.
```

It **never names a subscriber** — there is a test asserting the output contains
no "owner is" / "belongs to" / "registered to". Structure is derivable; identity
is not, and a tool that blurs the two libels people.

For a self-audit the useful finding is elsewhere: a number's real exposure is
**WhatsApp / Signal / Telegram showing a display name and photo to anyone who
saves it as a contact** — self-published, invisible to every search engine, and
fixable in each app's privacy settings in a minute.

### Name↔handle confirmation

For a **person** target, the loop tries to link the real name to account handles
— the *"Alex Marsh → AMarsh-Sec"* step. It works the way a search engine
actually does it, which is more boring than it looks: **the GitHub profile's own
`name` field says "Alex Marsh"**. Nothing is deduced; the link was published by
the account owner and merely noticed.

So the rule is: **a link is reported only when the account publicly declares the
name.** Candidates come from handles observed in results (strongest), then
context-spliced guesses (`amarsh-sec` from *"Alex Marsh, AI security"*), then
plain permutations — but where a candidate came from changes only its priority,
never its burden of proof.

```
GitHub: @amarsh-sec publicly declares "Alex Marsh"      → CONFIRMED
GitHub: @amarsh exists but names "Maciej Jarczok"           → NOT LINKED
GitHub: @jaylpz exists but names "Alex Lopez"            → NOT LINKED
```

Matching requires **every token** of the name: a profile declaring only "Linus"
does not confirm "Linus Torvalds". Supersets pass ("Dr Alex Marsh"), order does
not matter ("Jing Yi Wong" ≡ "Wong Jing Yi"), partial declarations never do.

That constraint is load-bearing rather than decorative. It makes the feature
useful for auditing your own exposure — *"your GitHub publicly states your real
name, and that declaration is what connects your handle to you; remove it and
the link breaks"* — while making it structurally useless for unmasking an
anonymous account, because an anonymous account does not declare a name. The
accounts someone would want to de-anonymise are exactly the ones that fail.

**Cross-platform username sweep** — when the **primary target is a bare handle**,
Black Noir also probes **22 clearnet sites** (GitHub, GitLab, Keybase, Steam,
Telegram, Bandcamp, Dev.to, Docker Hub, Chess.com, Last.fm, …) and reports every
platform where that handle exists. Presence is confirmed by status code or a
marker string — sites that soft-404 (return 200 for any name) were dropped, so a
hit means a real account, not a guess. Read-only, no downloads. The 22 checks run
**concurrently (6 at a time, ~8s total)**; each site is still hit exactly once,
and the guardrail audit log is thread-locked so it stays complete and verifiable.

**Breach/leak (optional):** with `INTELX_API_KEY`, an Intelligence X search runs
on username/email/domain/name targets.

Enrichment runs after the first correlation pass, **live-only**, JSON/text reads
only (never a file download), capped at 6 entity-enrichments per run. Turn off
with `--enrich off`. A 404 is treated as "not found", not an error. **Keyed
sources only ever fire when their key is present** — no silent key requirements;
without a key the equivalent stays a manual **pivot-toolkit** link in the runbook.

## Local file metadata (EXIF / GPS + document authorship)

Everything in `input/` is parsed **locally** — no network, nothing uploaded:

- **Images** (via Pillow) → **EXIF**: GPS coordinates become a clickable Google
  Maps link in the report, plus camera make/model, capture timestamp, editing
  software. Screenshots / scrubbed photos simply carry no EXIF and skip cleanly.
- **Documents** — PDF, Word/Excel/PowerPoint (`.docx/.xlsx/.pptx`) and
  OpenDocument (`.odt/.ods`) → **authorship metadata**: author, last-modified-by,
  title, create/modify dates, revision, application, company. Pure stdlib (PDF
  Info dict + OOXML/ODF `core.xml`); never runs a macro, follows a link, or
  extracts embedded files.

It's reading bytes already on your disk — this never leaves your machine.

---

## Defensive preflight (Docker + VPN)

Before a **live** search (`--preflight`):

| Mode | Behaviour |
|------|-----------|
| `off` | skip |
| `warn` *(default)* | check Docker+VPN; auto-start Docker Desktop if installed; spin up `docker-compose` (with consent); never blocks |
| `enforce` | Docker running **and** a VPN active required, else **downgrade to plan-only** (no network leaves the machine) |

- Missing Docker/VPN → offers a `winget` install (consent; `--yes` to auto-approve).
- VPN is auto-detected (WireGuard/OpenVPN/NordLynx/Proton/Mullvad/Tailscale/…);
  if none, it offers to install WireGuard (you connect it yourself).
- `Dockerfile` + `docker-compose.yml` run the sweep isolated behind a
  [gluetun](https://github.com/qdm12/gluetun) VPN gateway.

---

## Environment (`.env` or real env)

| Variable | Purpose |
|----------|---------|
| `BLACKNOIR_PROVIDER` | default provider (`auto` or a name) |
| `ANTHROPIC_API_KEY` / `ANTHROPIC_MODEL` | Claude |
| `OPENAI_API_KEY` / `OPENAI_MODEL` / `OPENAI_BASE_URL` | OpenAI |
| `GOOGLE_API_KEY` / `GOOGLE_MODEL` / `GOOGLE_BASE_URL` | Gemini |
| `NVIDIA_API_KEY` / `NVIDIA_MODEL` / `NVIDIA_BASE_URL` | NVIDIA NIM |
| `OLLAMA_MODEL` / `OLLAMA_BASE_URL` | local Ollama (auto-started) |
| `SERPER_API_KEY` | Google web results via Serper |
| `SAUCENAO_API_KEY` | reliable SauceNAO reverse-image |
| `HIBP_API_KEY` | HIBP **per-account** email lookups (domains work keyless) |
| `DEHASHED_API_KEY` / `DEHASHED_EMAIL` | DeHashed leaked-record lookups |
| `SHODAN_API_KEY` | **optional** — full Shodan host data on IP enrichment (org/OS/products/CVEs; keyless InternetDB always runs) |
| `NUMVERIFY_API_KEY` | **optional** — native carrier/line-type/region on phone targets |
| `INTELX_API_KEY` | **optional** — Intelligence X breach/leak search on username/email/domain/name targets |

**Breach lookups — what needs a key:** HIBP works **keyless for domain/company
targets** (real breach data via the public `?Domain=` endpoint) — no key needed.
A per-*account* email check (`is this email breached`) is the only part that
needs `HIBP_API_KEY`, because HIBP blocks keyless email enumeration by design.
DeHashed has no keyless endpoint and needs `DEHASHED_EMAIL` + `DEHASHED_API_KEY`.
**Tunables**

| Variable | Purpose |
|----------|---------|
| `BLACKNOIR_MAX_QUERIES` | query variations per engine (default 4; deep=10) |
| `BLACKNOIR_MAX_RESULTS` / `BLACKNOIR_MAX_MERGED` | result caps |
| `BLACKNOIR_HTTP_TIMEOUT` | per-request timeout seconds |
| `BLACKNOIR_DEEP_RECON_QUERIES` | opening sweep size (default 4; aliases extend it) |
| `BLACKNOIR_DEEP_WALL_DORKS` | `site:`/`filetype:` dorks per run (default 6; `0` disables) |
| `BLACKNOIR_DEEP_REFLECT_QUERIES` | retry queries the reflection may spend (default 4) |
| `BLACKNOIR_NAME_WINDOW` | characters within which parts of one name must co-occur (default 60) |
| `BLACKNOIR_IMPERSONATE` | **off by default.** `chrome`/`firefox`/`safari`/`edge` presents that browser's TLS fingerprint via `curl_cffi` — see below |

### `BLACKNOIR_IMPERSONATE` — read before enabling

By default Black Noir identifies itself honestly: a `BlackNoir-OSINT/1.0`
User-Agent over Python's ordinary TLS stack. That is deliberate — the same
commitment as the no-evasion rule in `guardrails.py` — and it is *why* some
engines refuse it.

Measured effect when enabled: **DuckDuckGo goes from `blocked` (HTTP 202
challenge) to 10 results.** Bing is unchanged (it serves decoys regardless).

Two things to know first:

- **It is all-or-nothing.** A browser TLS handshake carrying a `BlackNoir-OSINT`
  User-Agent is a *more* anomalous fingerprint than either half alone, so when
  impersonation is on the honest UA is dropped and `curl_cffi`'s matching
  browser headers are used. You cannot be half-honest at the transport layer.
- **It does not open login walls.** Instagram/Facebook/LinkedIn want a session,
  not a friendlier handshake.

Nothing else changes: no onion fetch, no download, no link-following, and a
served challenge page is still reported as `blocked` rather than worked around.
The lean exe does not bundle `curl_cffi`, so the setting is inert there — and
`transport_status()` says so rather than pretending it applied.

---

## Manual / Tor-only sources (Torch, Telepathy, dark-web-scraper)

These three have **no clearnet API**, so Black Noir doesn't auto-run them — it
hands them to you two ways:

**1. Manual runbook** (`output/runbook_<subject>_<time>.md`, on by default) — a
copy-paste checklist: the search terms, a **target-type pivot toolkit**
(ready-to-open OSINT tools tailored to the target — carrier/HLR + scam DBs for a
phone, HIBP/Epieos for an email, WhatsMyName for a username, WHOIS/crt.sh/Wayback
for a domain, Shodan/AbuseIPDB for an IP, blockchain explorers for a BTC address,
people-search for a name — plus toolkits for any typed entities it surfaced), the
onion links the clearnet indexes found (open in **Tor Browser**), the Telepathy
commands, and reverse-image upload links. Run them yourself in an isolated/
VPN-backed environment, then drop results into `input/` and re-run to correlate.

**2. Bring-your-own-tool** — wire a local command per source in `.env` and Black
Noir shells out to it on `--live` (args substituted safely, no shell injection):

```ini
TELEPATHY_CMD=telepathy -u {q}          # clearnet Telegram OSINT toolkit
DARKWEB_SCRAPER_CMD=my-scraper -q {q}   # your local Tor scraper
TORCH_CMD=                              # (Tor-only; your choice/responsibility)
```

`{q}` is replaced with the query. Whatever the tool prints becomes results and
is folded into the graph. Torch/dark-web-scraper are Tor-bound, so that's your
tool over your Tor — Black Noir itself still never touches an onion service.

## Personas, inbox & bounded send

A **persona** is a burner identity *you* create and operate; Black Noir tracks it
(the vault), warns before a live run leaks your real IP/identity (**opsec guard**),
reads your **own** inbox, **triages** who to answer first, and can send **one
human-triggered message at a time** — never automation.

- **Read is text-only:** links, attachments, and remote images are shown as
  **inert text, never opened** ("no virus" — extends the no-download guardrail).
- **Send is bounded:** one message per explicit command, **preview + y/N confirm**,
  official-API platforms only (Email/Gmail, Telegram, Meta own-inbox).
- **Not built:** AI account creation, AI operating accounts, cold-DM, reading
  others' private content, or any non-official-API platform (WhatsApp/TikTok/…).

```
blacknoir --list-personas
blacknoir --send "email:mom@example.com::hi mom"   # preview + y/N
blacknoir --triage                                 # rank your inbox
```
Chat: `/persona`, `/inbox`, `/triage`, `/send`. See **cookbook.md §11** for the
full reference and setup (Gmail App Password, etc.).

## Safety model (enforced in `blacknoir/guardrails.py`)

1. **No onion fetches** — `.onion` refused; found onion links kept as text only.
2. **No downloads** — executable/archive/document URLs refused.
3. **No untrusted hosts** — only registry + reverse-image + Serper hosts.
4. **No clicking** — reads search-index pages; follows zero result links.
   `/fetch <url>` is the one exception and is not the same thing: the rule
   exists because an agent picking its own next target *from an untrusted result
   page* can be steered by whoever controls that page. A human typing a URL
   chooses the target outside the loop. That host is authorised only for the
   session, logged as its own `authorize` audit event, and one page is read —
   links on it are listed and never followed.
5. **No internal addresses** — loopback, private ranges, link-local and cloud
   metadata (`169.254.169.254`, `localhost`, `*.local`) are refused for **every**
   host, allow-listed or operator-named, so `/fetch` cannot become an SSRF
   primitive aimed at the machine it runs on.
6. **Fetched pages are untrusted input** — text pulled in by `/fetch` enters the
   model's context tagged as content to report on, never as instructions to
   follow.
7. **No covert face-ID** — face engines are manual, labelled, consent-gated.
8. **No evasion by default** — an anti-bot page is reported `blocked`, not worked
   around. `BLACKNOIR_IMPERSONATE` is opt-in and documented above.
9. **Never names a phone subscriber** — structure is derivable, identity is not.
10. **Public only** — the agent is instructed never to seek private/non-public data.
11. **Auditable** — every allow/block/upload/authorize decision is logged in the report.

---

## Build & test (Windows)

```bat
dev\test.bat       :: pytest/unittest suite + smoke test
dev\build.bat      :: lean ~14 MB  dist\blacknoir.exe     (NO AI libs; heuristic only)
dev\build-ai.bat   :: AI  ~39 MB   dist\blacknoir-ai.exe  (bundles LLM SDKs)
run.bat ...        :: run the best available exe, else python main.py
```

**Which exe?**
- `blacknoir-ai.exe` — bundles the OpenAI/Anthropic SDKs, so **chat, AI planning
  and vision work standalone** with keys from `.env`. Use this for the chatbot.
- `blacknoir.exe` — lean; runs the deterministic heuristic agent (no LLM). Good
  for scripted searches where you don't need the AI.

Serper, SauceNAO, and IQDB work in **both**. The launchers
(`Black Noir (chat).bat`, `run.bat`) prefer `blacknoir-ai.exe` automatically.
Running from source (`python main.py …`) always has full AI.

`curl_cffi` is bundled in the **AI** build only, so `BLACKNOIR_IMPERSONATE`
works there and is inert (and says so) in the lean exe.

> **Rebuild after changing source.** A stale `.exe` still contains the old code,
> and the `.bat` launchers prefer the exe over source — so a fix you just made
> will not be in what double-clicking runs until you rebuild.

### How the relevance tests are built

Every relevance bug found in this codebase shared one root cause, and it was not
in the matcher — it was in the fixtures. Short synthetic strings, written to
match whatever the author already believed, cannot exhibit the failure mode real
pages have:

> In a long enough document, **every** common token appears somewhere.

A 20,000-character inter-school competition page naming 231 people contains
"Wong" 14 times and "Yi" 5 times — in other people's names. A matcher that only
asks *"is this token present?"* says yes, and a stranger's prize listing becomes
evidence about a specific teenager. A 40-character fixture never reveals that.

So three layers:

1. **Real corpus** (`tests/fixtures/noise_pages.json`) — actual fetched pages.
   Capture a new one with `/fetch` and add a row to `CORPUS`.
2. **Adversarial generator** — documents built from the tokens that break naive
   matching, scaled to 400 names, asserting the invariant that generalises:
   *a document not containing the target's name is never about the target,
   however long it is or however many other names it holds.*
3. **Mutation guard** — reintroduces each historical bug and asserts the corpus
   suite **fails**. A mutation that survives means that guard is decorative.

That third layer earned itself twice while being written: a word-boundary
mutation survived because the rule was duplicated in two functions and the
untouched copy held the line (fixed by making one define the other), and the
CJK name-order branch turned out to have **no failing case at all**, because
every existing test put the full name in the document verbatim and
short-circuited before that logic ran.

Adding a mutation is one row in `MUTATIONS`.

---

## Project layout

Root holds the **things you run**; everything else is tucked into folders.

```
▶ main.py                    run from source:  python main.py …
▶ Black Noir (chat).bat      double-click → interactive chatbot
▶ Black Noir (terminal).bat  double-click → shell with `blacknoir` command
▶ run.bat                    run the best available exe (or source)
  README.md  requirements.txt  .env / .env.example

blacknoir/                 the source package
  cli.py                  argument parsing, banner
  chat.py                 interactive chatbot REPL
  pipeline.py             parse → plan → collect → reverse → correlate → synth → report
  agent.py                AI brain (parsing, planning, synthesis, vision)
  intent.py               natural-language target parser
  llm.py                  multi-provider LLM + failover
  config.py               source registry           guardrails.py  safety
  http.py                 network layer (GET+POST)  entities.py    correlation
  deepsearch.py           the candidate loop: recon → reflect → cluster → dive
  handles.py              name↔handle confirmation (declared-name rule)
  phone.py                keyless numbering-plan analysis
  webfetch.py             operator-directed single-page fetch (/fetch)
  selfaudit.py            self-audit checks (Pwned Passwords, k-anonymity)
  inputs.py               input/ processing         reverse_image.py  reverse search
  report.py               HTML report               report_pdf.py  PDF report
  preflight.py            Docker + VPN checks        env.py  models.py
  connectors/             one adapter per source (+ Serper)

dist/                     built executables (blacknoir-ai.exe, blacknoir.exe)
dev/                      build & test tooling (build*.bat, test.bat, *.spec)
docker/                   Dockerfile, docker-compose.yml
tests/                    offline unit suite (371 tests)
  test_core.py              the original suite
  test_handles_and_fixes.py handle confirmation, phone, /fetch, report honesty
  test_relevance_corpus.py  REAL fetched pages + generated adversarial ones
  test_mutation_guard.py    asserts the relevance tests can actually FAIL
  fixtures/                 captured page text, so tests run offline
input/                    drop target context (text, images) here
output/                   generated reports (.html + .json + .pdf)
```

Build/test from `dev/`: `dev\build-ai.bat`, `dev\build.bat`, `dev\test.bat`.

---

## Responsible use

Black Noir searches for information about **real people**. That carries
obligations, and the tool cannot enforce them for you.

**Before you run it on someone:**

- Have a lawful basis and, where required, authorization. "It's public" is not
  the same as "it's fair game" — most jurisdictions regulate the *aggregation*
  of individually-public facts into a profile.
- Be aware of local data-protection law. Hong Kong's PDPO, the UK/EU GDPR, and
  similar regimes apply to profiling regardless of where the data was found.
- Take particular care with **minors**. Assembling a dossier on a child from
  school pages, award lists and sports records is trivially easy with a tool
  like this, and is very rarely defensible.
- Remember that people who are *not* your target appear in your results —
  classmates, colleagues, family. They did not consent to being indexed either.

**What the tool deliberately will not do:**

- It does **not** identify a person from their face. The vision pass reads
  visible *marks* — handles, watermarks, signage, logos — and reasons about
  *setting*. It never infers "this face belongs to <name>", and returns no
  leads at all when a face is the only content. Facial-recognition services are
  offered as manual links, never auto-uploaded.
- It does **not** connect to `.onion` services, download files, or follow
  result links. It reads search-index metadata only, and every network decision
  is allow-listed and logged.
- It does **not** report an unresolved identity as a confident finding. When
  candidates cannot be separated, it asks you a question instead of guessing.

**Data it stores locally:** reports in `output/`, investigation memory in
`memory/`, and anything you place in `input/`. All three contain personal data
and are gitignored by default. Review them, and use `--forget "<target>"` or
`--forget-all` to erase remembered identities.

If you are not sure whether a particular search is appropriate, that hesitation
is usually correct.
