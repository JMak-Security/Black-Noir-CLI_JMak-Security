# Black Noir — Cookbook

Every flag, every chat command, every env var, plus copy-paste recipes.

`run.bat` = the launcher (uses `dist\blacknoir-ai.exe` if built, else `blacknoir.exe`,
else `python main.py`). Anywhere below you can swap `run.bat` for `python main.py`.

---

## 1. Ways to run

| How | Command | Notes |
|-----|---------|-------|
| Double-click chat | **`Black Noir (chat).bat`** | interactive chatbot (AI + `/search`) |
| Double-click shell | **`Black Noir (terminal).bat`** | opens a prompt where `blacknoir …` works |
| From source | `python main.py <target> [flags]` | full AI (needs `.env` keys) |
| Built exe | `dist\blacknoir-ai.exe <target> [flags]` | self-contained AI build |
| Launcher | `run.bat <target> [flags]` | picks the best available |

---

## 2. CLI flags (complete)

```
blacknoir <target> [options]
```

`<target>` = a name, `@handle`, username, email, domain, phone — **or a
free-form instruction** ("This is Jensen Huang, find every public detail").
Omit it with `--chat`, `--doctor`, or `--list-sources`.

| Flag | Values (default) | What it does |
|------|------------------|--------------|
| `--surface` | `public` \| `darkweb` \| `all` (**all**) | which surface(s) to search |
| `--live` | (off) | actually hit the network; without it = **plan-only** (prepares queries, fetches nothing) |
| `--chat` | (off) | open the interactive chatbot; any target text becomes the first message |
| `--provider` | `auto`\|`anthropic`\|`openai`\|`google`\|`nvidia`\|`ollama` (**auto**) | LLM backend; `auto` picks the first configured + fails over on errors |
| `--model` | model id (provider default) | override the model for the chosen provider |
| `--no-llm` | (off) | force the deterministic heuristic agent (no LLM calls) |
| `--reverse-image` | `auto` \| `off` (**auto**) | reverse-image search on input images (SauceNAO/IQDB + links) |
| `--enrich` | `auto` \| `off` (**auto**) | native enrichment of domains/IPs/BTC/handles via keyless official APIs + cross-platform username sweep (live-only) |
| `--preflight` | `off` \| `warn` \| `enforce` (**warn**) | Docker+VPN check before a live search |
| `--yes`, `-y` | (off) | auto-approve preflight install/start/spin-up prompts |
| `--doctor` | (off) | run the Docker+VPN checks and exit |
| `--only` | `k1,k2` | restrict to specific source keys (see §4) |
| `--max` | (off) | **MAX mode** — throw everything at ONE target: all surfaces, every available source, deep multi-round loop, and the biggest query/budget knobs. Bundles `--surface all --all-sources --deep-loop on` + boosted `BLACKNOIR_DEEP_*`. Best for "find every leak" runs. **Uses more API credits.** |
| `--all-sources` | (off) | query **every** applicable source, not just the planner's pick |
| `--no-pdf` | (off) | skip the PDF report (PDF is on by default) |
| `--no-runbook` | (off) | skip the manual runbook (Tor/Telepathy steps) |
| `--input-dir` | path (**input**) | folder of context files/images to process |
| `--output-dir` | path (**output**) | where reports are written |
| `--quiet` | (off) | suppress progress output |
| `--list-sources` | (off) | list all sources + LLM providers and exit |
| `--check-password` | (off) | **self-audit:** check ONE of your own passwords against the HIBP corpus and exit. Prompts without echo (`getpass`), so it stays out of your screen, shell history and process list. Needs `--live` |
| `--version` | | print version and exit |

```bash
# is a password of mine burned?  (k-anonymity: only 5 hash chars are sent)
python main.py --check-password --live
```

**Depth** isn't a flag — it's inferred from the instruction. Words like
*everything / every / all / comprehensive / deep / secret* trigger a **deep**
sweep (more queries + every available source). `--all-sources` forces the same
source coverage regardless of wording.

---

## 3. Chat commands (complete)

Inside `--chat`. Plain text that looks like a search (`who is…`, `investigate…`,
`search…`) runs a search; anything else is answered by the LLM.

| Command | What it does |
|---------|--------------|
| `/search <instruction>` (`/investigate`, `/s`) | run an investigation with current settings |
| `/live on\|off` | fetch real results vs dry-run (**chat defaults to ON**) |
| `/preflight off\|warn\|enforce` | Docker+VPN gate for live (**chat defaults to off**) |
| `/surface public\|darkweb\|all` | which surface(s) |
| `/provider <name>` | switch LLM backend (auto/anthropic/openai/google/nvidia/ollama) |
| `/model <id>` | override the model |
| `/deep on\|off` | force comprehensive queries + **every** engine |
| `/max on\|off` | **MAX mode** — all surfaces + every source + deep multi-round loop + full panel for the next searches. For the biggest per-engine query budget too, launch once with `python main.py --max --chat` |
| `/reverse on\|off` | reverse-image on input images |
| `/input` | analyse the `input/` folder now (files + images) |
| `/fetch <url>` | read ONE page you name, as text; needs `/live on`. Lists the links it contains and **follows none**. The page enters chat context tagged as untrusted content. (For reading + fact-extraction + crawling, use `/read` below.) |
| `/candidates` (`/cands`) | list same-name candidates + constraint fit |
| `/focus <n>` (`/pick`) | pursue ONLY candidate `<n>`; everyone else is ruled out as a namesake and never profiled |
| `/dig [n]` (`/deepdive`, `/autopilot`) | **relentless autonomous deep-dive** on the confirmed candidate — the agent self-directs round after round (judge → extract identifiers → propose its own next queries) until the lead is exhausted. `n` optional after `/focus`. Repeat `/dig` to push further (already-run queries are skipped). Depth, not breadth. |
| `/read [url]` (`/detective`, `/deepread`) | **detective read** — FETCH and read the FULL pages that name the target (not snippets), extract facts grounded in the real text, like an AI overview. `/read` (no arg) auto-discovers the institution in the context and merges its **sitemap + homepage + Wayback** index; `/read <page-url>` / **pasting a bare URL** runs a read-only **agentic crawl** from that URL — it reads the page, the model reasons which links lead toward the target, follows them, repeats (bounded step budget). Reads snippet-free, so it also *kills* the splice errors. Needs `/live on`. |
| `/refine <detail>` (`/more`, `/also`) | add what you know; re-narrows the candidate list |
| `/memory` / `/memory off\|on` / `/forget <target>` / `/forget all` | inspect or erase what past runs remembered |
| `/sources` | list all search sources |
| `/last` | show the last report path |
| `/settings` | show current settings |
| `/clear` | clear the conversation history |
| `/help` | list commands |
| `/exit` (`/quit`, `/q`) | leave chat |

**Use every engine in chat:** run `/deep on` once, then search — or phrase it as
"find everything about X".

---

## 4. Source keys (for `--only`)

Current registry (bot-blocked & paid-only sources were removed):

| Surface | Key | Source | Notes |
|---------|-----|--------|-------|
| public | `bing` | Bing | keyless scrape |
| public | `serper` | Serper (Google) | needs `SERPER_API_KEY` |
| darkweb | `ahmia` | Ahmia.fi | keyless onion index |
| darkweb | `lyzem` | Lyzem | keyless Telegram index (noisy) |
| darkweb | `hibp` | Have I Been Pwned | **keyless for domains**; per-account email needs `HIBP_API_KEY` |
| darkweb | `xposed` | XposedOrNot | **keyless per-email breach check** — fills HIBP's keyless-email gap; email targets only (~100/day per IP) |
| darkweb | `intelx` | Intelligence X | leak/paste/darknet index; needs `INTELX_API_KEY` (free dev key ~50 searches; comma-separate several for failover) |
| darkweb | `telepathy` | Telepathy | runs if `TELEPATHY_CMD` set (else manual/runbook) |
| darkweb | `torch` | Torch | Tor-only → manual/runbook (or set `TORCH_CMD`) |
| darkweb | `darkweb_scraper` | dark-web-scraper | manual/runbook (or set `DARKWEB_SCRAPER_CMD`) |

Reverse-image engines (auto when images are in `input/`): SauceNAO + IQDB
(real uploads) and prepared links (Yandex, Google Lens, Bing Visual, TinEye;
+ PimEyes/FaceCheck for person photos, manual).

---

## 5. Environment variables (`.env` or real env)

**Provider selection**
| Var | Purpose |
|-----|---------|
| `BLACKNOIR_PROVIDER` | default provider (`auto` or a name) |

**LLM providers** (each: key, optional model, optional base URL)
| Var | Purpose |
|-----|---------|
| `ANTHROPIC_API_KEY` / `ANTHROPIC_MODEL` | Claude |
| `OPENAI_API_KEY` / `OPENAI_MODEL` / `OPENAI_BASE_URL` | OpenAI |
| `GOOGLE_API_KEY` / `GOOGLE_MODEL` / `GOOGLE_BASE_URL` | Gemini (AI Studio) |
| `NVIDIA_API_KEY` / `NVIDIA_MODEL` / `NVIDIA_BASE_URL` | NVIDIA NIM |
| `OLLAMA_MODEL` / `OLLAMA_BASE_URL` | local Ollama (auto-started) |

**Search / data keys**
| Var | Purpose |
|-----|---------|
| `SERPER_API_KEY` | Google web results via Serper |
| `SAUCENAO_API_KEY` | reliable SauceNAO reverse-image (optional) |
| `HIBP_API_KEY` | HIBP per-account email lookups (domains are keyless) |
| `SHODAN_API_KEY` | optional — full Shodan host data on IP enrichment (keyless InternetDB always runs) |
| `NUMVERIFY_API_KEY` | optional — carrier/line-type/region on phone targets. **Keyless numbering-plan analysis runs regardless** |
| `INTELX_API_KEY` | optional — Intelligence X breach/leak search (username/email/domain/name) |

_Enrichment sources that need **no** key: crt.sh, Google DoH, Wayback, Shodan
InternetDB, Blockstream, GitHub, Reddit, Bluesky, Mastodon, **Pwned Passwords**
(k-anonymity), **phone numbering-plan analysis** (fully offline), and the 22-site
username sweep. Keyed vars above only fire when set — no silent key requirement._

**External local tools** (shelled out on `--live`; use `{q}` for the target)
| Var | Example |
|-----|---------|
| `TELEPATHY_CMD` | `telepathy_env/Scripts/telepathy.exe -t {q}` |
| `DARKWEB_SCRAPER_CMD` | `my-scraper -q {q}` |
| `TORCH_CMD` | (your Tor-capable tool) |

**Tuning**
| Var | Default | Purpose |
|-----|---------|---------|
| `BLACKNOIR_MAX_QUERIES` | 4 (deep: 10) | query variations per engine |
| `BLACKNOIR_MAX_RESULTS` | 15 | results kept per source per query |
| `BLACKNOIR_MAX_MERGED` | 30 | merged results cap per source |
| `BLACKNOIR_HTTP_TIMEOUT` | 20 | per-request seconds |
| `BLACKNOIR_ERROR_THRESHOLD` | 2 | LLM errors before provider failover |
| `BLACKNOIR_DEEP_RECON_QUERIES` | 4 | opening sweep size (aliases extend it) |
| `BLACKNOIR_DEEP_WALL_DORKS` | 6 | `site:`/`filetype:` dorks per run; `0` disables |
| `BLACKNOIR_DEEP_REFLECT_QUERIES` | 4 | retry queries the reflection may spend |
| `BLACKNOIR_DEEP_QUERY_BUDGET` | 40 | hard ceiling on queries per deep run |
| `BLACKNOIR_NAME_WINDOW` | 60 | chars within which parts of one name must co-occur |
| `BLACKNOIR_IMPERSONATE` | *(off)* | `chrome`/`firefox`/`safari`/`edge` — browser TLS fingerprint via `curl_cffi` |

**`BLACKNOIR_IMPERSONATE` — the honest-transport trade**

Off by default: Black Noir identifies itself as `BlackNoir-OSINT/1.0` over
Python's TLS, which is deliberate and is *why* some engines refuse it.

| | honest (default) | `=chrome` |
|---|---|---|
| DuckDuckGo | `blocked` (HTTP 202 challenge) | **ok, 10 results** |
| Bing | ok (decoy-filtered) | ok (decoy-filtered) |
| login walls | closed | **still closed** — they want a session, not a handshake |

It is all-or-nothing: when on, the honest UA is dropped, because a browser TLS
handshake carrying a scraper User-Agent is a *louder* signal than either half.
Bundled in the **AI exe only**; inert in the lean exe, which says so rather than
pretending. A typo'd value falls back to honest transport with a clear message —
`curl_cffi` validates lazily, so an unvalidated typo would otherwise fail every
request and look like "every source is blocked".

---

## 6. Recipes

**Person, everything, live**
```
run.bat "This is Jensen Huang, find every public detail" --live
```

**Domain/company breach + dark-web (keyless HIBP fires here)**
```
run.bat "tesla.com" --surface all --live
```

**Username across the dark-web surface**
```
run.bat "@nightowl" --surface darkweb --live
```

**Email — public + breach**
```
run.bat "john.doe@example.com" --surface all --live
```

**Auditing your own exposure** — the easy problem, because you already know the
answer. Self-audit needs no identity resolution: you supply the identifiers the
tool would otherwise have to infer.
```
python main.py --check-password --live       # is one of my passwords burned?
run.bat "@my_actual_handle" --surface all --live   # 22-site presence sweep
run.bat "me@mydomain.com"   --surface all --live   # breach + enrichment (XposedOrNot fires KEYLESS here)
run.bat "mydomain.com"      --surface all --live   # keyless HIBP fires here
```
> **No paid key needed to check an email for breaches.** `xposed` (XposedOrNot)
> answers per-email keylessly, so `me@mydomain.com` returns real breach hits even
> without `HIBP_API_KEY`. Add `HIBP_API_KEY` (~$4.50/mo) later for the larger
> corpus, and free `INTELX_API_KEY`(s) for paste/combolist coverage.
Then, by hand, the parts no crawler can reach: WhatsApp/Signal/Telegram profile
visibility, "who can find me by number", search-engine indexing of your social
profiles, and friends/followers list privacy — that last one is the graph edge
that makes you walkable from a single known fact.

**Phrase a person search name-first** — the quoted segment becomes the subject,
so leading with a phone number targets *the number*, not the person:
```
✗ run.bat "search \"+852 5550 0100\", owner is Wong Jing Yi, student at ..."
✓ run.bat "search \"Wong Jing Yi\", chinese name \"王婧兒\", student at 高雷中學 Hong Kong, phone +852 5550 0100"
```
The second form makes the target a `name` (so the login-wall dorks and handle
confirmation run at all), keeps the native-script alias as a first-class query,
and leaves the phone number as *context* — which is what it's good for.

**Read a page the search engine only summarised**
```
/live on
/fetch https://example.edu/achievement      # one page, as text, links not followed
```

**Reverse-image "who drew / who is this"** (drop the image in `input/` first)
```
run.bat "who drew this art" --live
run.bat "who is this" --live          # person photo → face-engine links
```

**Use ONE engine only**
```
run.bat "vxunderground" --surface darkweb --only telepathy --live --preflight off
run.bat "adobe.com"      --surface darkweb --only hibp      --live --preflight off
run.bat "OSINT tools"    --surface public  --only serper    --live --preflight off
```

**Use EVERY engine (force)**
```
run.bat "acme corp" --surface all --all-sources --live
```

**Plan-only (see what WOULD run, no network)**
```
run.bat "target" --surface all           # no --live
```

**Pick / force a provider or model**
```
run.bat "target" --provider nvidia --live
run.bat "target" --provider google --model gemini-1.5-pro --live
run.bat "target" --no-llm --live          # deterministic, no AI
```

**Hard-gate live on Docker+VPN (else downgrades to plan-only)**
```
run.bat "target" --live --preflight enforce
run.bat "target" --live --yes             # auto-approve start/install
```

**Housekeeping / info**
```
run.bat --list-sources
run.bat --doctor                          # Docker+VPN check
run.bat --chat                            # interactive
```

**Skip outputs**
```
run.bat "target" --live --no-pdf --no-runbook
```

**Chat: maximum coverage session**
```
run.bat --chat
  /deep on
  /surface all
  investigate tesla.com
```

---

## 7. Telepathy quick recap

1. Login lives in the folder you run it from. Keep `+<phone>.session` and
   `telepathy_files/login.txt` in the **project root** (Black Noir runs from there).
2. `.env`: `TELEPATHY_CMD=telepathy_env/Scripts/telepathy.exe -t {q}`
   (use `-u {q}` for a user id instead of a channel).
3. Run: `run.bat "<channel>" --surface darkweb --only telepathy --live --preflight off`
4. Full dumps land in `telepathy_files/<channel>/` — drop them into `input/` and
   re-run to correlate everything.

---

## 8. Output files (in `output/`)

| File | What |
|------|------|
| `report_<subject>_<time>.html` | interactive entity graph + findings (open this) |
| `report_<subject>_<time>.pdf` | printable summary |
| `report_<subject>_<time>.json` | raw machine-readable data |
| `runbook_<subject>_<time>.md` | manual steps for Tor-only / external sources |

---

## 9. Safety one-liners

- No `--live` = nothing leaves your machine.
- `.onion` is never fetched; found onion links are text-only (see the runbook).
- Nothing is downloaded; no result link is followed.
- Face-recognition engines are manual links only (authorization/consent required).
- Run behind a VPN (`--preflight`), read-only on Telegram, guard `.env` + `.session`.

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| **Every source says "planned", 0 results** | you're in plan-only mode | add **`--live`** (chat is live by default) |
| **exe window flashes and closes** | it's a CLI; double-click runs it with no args → prints help → exits | use **`Black Noir (chat).bat`** / `(terminal).bat`, or run from a terminal |
| **chat: "heuristic (no provider could start)" / no AI answers** | running the **lean** `blacknoir.exe` (no AI libs), or no provider key | use **`blacknoir-ai.exe`** (or `python main.py`), and fill a key in `.env` |
| **`agent: heuristic (...)` from source** | no LLM SDK / no key / all providers failed | `pip install openai` (or `anthropic`); check `.env`; try `--provider google` |
| **provider prints "failover: X → Y"** | X errored twice (bad model, rate limit, quota) | normal — it auto-switched. Pin one with `--provider`; tune `BLACKNOIR_ERROR_THRESHOLD` |
| **a source shows "blocked"** | the site bot-blocked/rate-limited the scrape (or SauceNAO keyless throttle) | expected — use the working engines; add `SAUCENAO_API_KEY` for reliable reverse-image. No evasion by design. |
| **HIBP "skipped: needs HIBP_API_KEY"** | you searched an **email/username** with no key | search the **domain** instead (keyless), or add `HIBP_API_KEY` |
| **Telepathy "command not found"** | `TELEPATHY_CMD` path wrong, or not run from project root | use the venv path `telepathy_env/Scripts/telepathy.exe -t {q}`; run from the project folder (launchers do) |
| **Telepathy "unable to open database file"** | `login.txt` has a trailing newline, or the session isn't in the run folder | write `login.txt` with **no trailing newline**; keep `+<phone>.session` in the project root |
| **Telepathy re-prompts API ID / "Aborted!"** | no `login.txt`/session where it's launched | log in once **from the project root**, or copy your `+<phone>.session` there |
| **Telepathy crashes on a target (`web_req` error)** | Telepathy's own bug on some users/edge targets | use public **channels/groups** (works); switch `-t`→`-u` for user ids |
| **Installing a tool broke the AI (httpx/openai errors)** | the tool downgraded shared deps | install it in its **own venv** (like `telepathy_env/`); restore with `pip install "httpx>=0.28,<1" "click>=8.1.7"` |
| **Docker Desktop launches on a live search** | preflight `warn` auto-starts it | use `--preflight off` (chat already defaults off) |
| **"Please create app" ERROR on my.telegram.org** | Telegram's flaky app page | VPN **off**, Short name 5–32 chars, Description filled; reload `/apps` — it often created it anyway |
| **garbled emoji/box chars in the terminal** | Windows codepage | cosmetic only — the HTML/PDF/JSON reports are correct UTF-8 |
| **noisy entities (huge "phone" numbers, forum domains)** | over-eager identifier extraction | trust the named handles/domains/emails; ignore long-digit "phones" and forum hosts |
| **DuckDuckGo / Haystak / DeHashed missing from `--list-sources`** | removed (bot-blocked / paid-only) | by design — Serper covers Google; keyless HIBP covers domain breaches |
| **a fix you just made isn't happening** | the `.bat` launchers prefer `dist\*.exe`, and a stale exe still holds the old code | rebuild: `dev\build-ai.bat` (and `dev\build.bat`) |
| **login-wall row says "NOT SEARCHED"** | your SERP plan **strips `site:`/`filetype:`** before searching, so the dorks were never really run | it is reported as `blocked`, never `empty` — an unsearched platform must not read as a clean one. Needs a plan that permits operators |
| **`BLACKNOIR_IMPERSONATE` seems to do nothing** | you're on the **lean** exe (no `curl_cffi` bundled), or the value is a typo | use `blacknoir-ai.exe` / source; valid values are `chrome`, `firefox`, `safari`, `edge` (a typo falls back to honest transport and says so) |
| **results are all about the school/employer, not the person** | a context-qualified query hands the engine two subjects and it ranks the one with thousands of pages | the recon row now states the split (*"12 about the person, 8 about the context only"*); an alias goes out **unqualified** first. Above a 2:1 ratio a note is added |
| **a source says `error: PARSER BREAK (suspected)`** | HTTP 200 with a long, link-dense body but our selector extracted nothing — the site redesigned | it is deliberately **not** reported as `empty`: this is a bug here, not an absence of results for your target. Fix the selector in `connectors/` |
| **candidate `match` is high but the evidence names nobody** | clustering scored the **context**, not the person | `_grade` counts only evidence that names the individual, so it will not reach `confirmed` — check the evidence list, not the score |
| **the loop asks about a spelling you're sure of** | the panel saw the results consistently use different characters | it **asks**, never substitutes — a model that is confidently wrong would otherwise retarget the whole search silently. Ignore it if you're right |
| **a name↔handle link you expected is missing** | the account does not publicly declare the name | by design: a link is reported only when the account itself states it. An anonymous account is *supposed* to fail this |

---

## 11. Reading a result honestly

The distinctions the report is careful about, and why each exists:

| Status | Means | Does **not** mean |
|---|---|---|
| `empty` | the source answered and had nothing | the target has no footprint |
| `blocked` | we were refused, or could not ask | the target has no footprint |
| `skipped` | never ran (no key, wrong target type) | coverage |
| `error: PARSER BREAK` | **our** selector is stale | an absence of results |
| `derived` | a conclusion drawn from the sources above | a source that was queried |

Sources queried / live hits count **only real sources** — identity candidates are
conclusions, and counting them inflated 5 real sources into a reported 9.

A candidate outcome of `dry` now means *no evidence*, not *the last round added
nothing new* — those are opposite conclusions, and conflating them threw away
evidence already in hand.
| **nothing on the dark web for a person** | clean public figures have little dark-web presence | expected — aim dark-web at **domains, emails, breached entities, handles** |

---

## 12. Personas, inbox & bounded send

A **persona** is a burner identity *you* create and operate; Black Noir only
tracks it and helps you read/triage/send **one message at a time, human-gated**.

### Boundaries (enforced in code)
- **Reads never fetch:** links, attachments, and remote images are shown as
  **inert text**, never opened ("no virus").
- **Sends:** one message per explicit command, **preview + y/N confirm**, no
  automation/loops/bulk, official-API platforms only.
- **Not built:** AI account creation, AI operating accounts, cold-DM, reading
  other users' private content, or any non-official-API platform.

### Channels
| Channel | Read | Send | Setup |
|---------|------|------|-------|
| **email** (Gmail) | ✅ inbox | ✅ | `EMAIL_ADDRESS` + `EMAIL_APP_PASSWORD` |
| **telegram** | (via Telepathy) | ✅ | Telethon + your session |
| **instagram / facebook / threads** | own inbox | reply-in-window | Meta app + `META_ACCESS_TOKEN` + App Review |

Excluded (no official API): WhatsApp personal, TikTok, Snapchat, Discord self-bots.

### CLI
```
blacknoir --list-personas
blacknoir "target" --persona nightowl --live      # opsec + report identity
blacknoir --send "email:mom@example.com::hi mom"  # preview + y/N, one message
blacknoir --triage                                # rank your inbox
```

### Chat commands
```
/persona list | new <name> | use <name> | show [name] | add-account <name> <platform> <user> [email] | rm <name>
/inbox [provider] [n]      read your own inbox (sanitized)
/triage                    rank who to answer first
/send <provider> <recipient> <message>    one message, preview + y/N
```

### Env
```ini
EMAIL_ADDRESS=            EMAIL_APP_PASSWORD=      # Gmail App Password
IMAP_HOST=imap.gmail.com  SMTP_HOST=smtp.gmail.com
TELEGRAM_SESSION=  TELEGRAM_API_ID=  TELEGRAM_API_HASH=
META_ACCESS_TOKEN=  IG_BUSINESS_ID=  FB_PAGE_ID=  THREADS_USER_ID=
```

### Opsec guard
On any live search, if VPN is off or no persona is active, Black Noir prints a
`⚠ opsec:` warning (real IP / real identity exposure). It never blocks — it warns.

### Commenting
| Platform | Comment on others? | Notes |
|----------|--------------------|-------|
| **youtube** | ✅ any video | read comments (`YOUTUBE_API_KEY`); post one (`YOUTUBE_OAUTH_TOKEN`, OAuth2) |
| **threads** | ✅ public threads | reply to a public thread (`THREADS_ACCESS_TOKEN`) |
| **instagram / facebook** | ❌ own posts only | reply to comments on YOUR posts (missing API for others) |

```
blacknoir --comment "youtube:dQw4w9WgXcQ::great video"   # preview + y/N
```
Chat: `/comment <provider> <target> <text>` (one comment, preview + y/N) and
`/comments youtube <video>` (read a video's comments). Same rule as sending:
one per explicit command, honest content, no automation.

> IG/FB can't comment on a *target's* post via ANY tool — it's a missing API
> endpoint, not an automation limit. Only YouTube (any video) and Threads
> (public) allow it officially.

---

## 13. Pivot chains — widen any seed into everything (and break each link)

OSINT is **pivoting**: a seed of *one* type fans out into the strong,
machine-checkable keys (*email · handle · domain · IP*) that carry real depth,
and each of those fans out again. Below, **every input category** the tool
accepts is shown as a "widen" chain — what it expands into, which keys it **feeds
back into**, and the 🛡 **blue-team break** that snaps the link. Read as a
defender: cut any one arrow and the fan-out stalls.

> **Scope reminder.** These chains de-anonymize a *specific* target. Run them on
> **yourself, your own org, or a subject who explicitly asked** — see
> README → *Scope → Effective ≠ acceptable*. Verification / probing steps touch
> real accounts and are detectable.

Legend: **feeds →** = which other seed chain the result drops you into.

---

### 📧 email — the richest single seed

| Widen step | Method | Yield |
|---|---|---|
| breach lookup | HIBP per-account · IntelX · DeHashed | passwords, **other emails**, phones, usernames |
| local-part flip | `nightowl@…` → try `@nightowl` everywhere | a **handle** (feeds → username) |
| Gravatar | md5(email) → avatar + linked profile | photo, sometimes real name |
| string search | the address in Serper/Bing, paste sites, resumes | forum posts, leaks, CVs |
| recovery probe | "forgot password" on major services | masked phone / recovery-email hints |
| domain part | `@corp.com` → the org | feeds → domain |

**feeds → username · phone · domain.** 🛡 **break:** unique address per service
(plus-aliases / catch-all), 2FA, no password reuse — makes a recovered email inert.

### 🌐 domain — the org fan-out

| Widen step | Method | Yield |
|---|---|---|
| CT logs | crt.sh | **subdomains** (dev/staging/vpn/mail) |
| DNS | Google DoH · passive DNS (Mnemonic) | A/AAAA (→ **IP**), MX (mail vendor), NS, TXT (SPF/DKIM → SaaS vendors) |
| WHOIS/RDAP | RDAP | registrant org/email (if unredacted), dates |
| history | Wayback | old staff pages, **leaked emails**, retired hosts |
| co-hosting | reverse-IP · hostsearch | other domains on the same box |
| site scrape | the homepage/contact/PDF authors | **names, emails, phones**, address |

**feeds → ip · email · name.** 🛡 **break:** WHOIS privacy, split prod/dev infra,
guessable-subdomain hygiene, minimise public staff/contact listings.

### 🖧 IP — the infrastructure fan-out

| Widen step | Method | Yield |
|---|---|---|
| service scan | Shodan InternetDB (keyless) / full | open ports, banners, **CVEs**, hostnames, org |
| reverse | reverse-IP · passive DNS | **domains** hosted there (feeds → domain) |
| cert | TLS cert SANs on the host | more domain names |
| geo/ASN | ASN + geolocation | hosting org, region |

**feeds → domain.** 🛡 **break:** patch/limit exposed services, put origin behind
a CDN/proxy so the real IP never resolves, firewall management ports.

### 👤 username / @handle — the identity fan-out

| Widen step | Method | Yield |
|---|---|---|
| presence sweep | `investigate @nightowl` → 22-site check | which platforms it exists on (status-code confirmed) |
| profile scrape | enrich GitHub/Reddit/Bluesky/Mastodon + open each | real name, bio, location, links, **other handles**, listed email |
| git email leak | GitHub commit metadata (`user.email`) | a **real, unguessed email** (feeds → email) |
| breach/combolist | the handle as a key in IntelX/DeHashed | emails, passwords, phones |
| string search | raw handle in engines, paste sites, Gravatar | reused-handle accounts engines missed |

**feeds → email · name.** 🛡 **break:** unique handle per context, `noreply` git
commit email, locked-down profile fields, 2FA + no reuse.

### ☎ phone — the contact fan-out

| Widen step | Method | Yield |
|---|---|---|
| **structure** | **numbering plan (keyless, offline — always runs)** | country, line type, and an explicit *"carrier not determinable"* where portability makes it so |
| carrier lookup | Numverify (keyed) · HLR | carrier, line type, region, ported status |
| reverse lookup | Truecaller-style DBs, runbook pivots | **name**, associated listings |
| app presence | Telegram/WhatsApp/Signal "find by number" | profile, photo, **handle** |
| string search | the number in engines, classifieds, combolists | leaked listings, breach rows |
| recovery probe | which services accept it for reset | confirms account ownership |

**feeds → name · username.** 🛡 **break:** VOIP/alias number for public signups,
lock "who can find me by number" in messaging apps, 2FA via app not SMS.

**Reading a "nothing found" on a phone number.** Most jurisdictions have **no
public mobile subscriber directory** — Hong Kong included. A zero-result sweep
there is not thin coverage or a weak index; the data does not exist on the open
web for anyone. Sites claiming otherwise are data brokers guessing, and their
records are stale and frequently wrong, which is why the reverse-lookup row above
stays a manual runbook pivot rather than something the tool reports as a finding.

Black Noir will therefore never name a subscriber, and there is a test asserting
its phone output contains no "owner is" / "belongs to" / "registered to".

```
+852 5550 0100 — Hong Kong · mobile · carrier not determinable
· No area codes — the leading digit is the service block, not a location.
· Portability since 1999 → the prefix says nothing about the current operator.
· No public subscriber directory exists for HK mobiles.
```

**The exposure that actually matters** (and the one to check on your own number):
**WhatsApp / Signal / Telegram show a display name and photo to anyone who saves
the number as a contact.** Self-published, invisible to every search engine,
fixable in each app's privacy settings in a minute. In Hong Kong, check a
suspicious number against **Scameter** (cyberdefender.hk) and call **18222**
(ADCC) if it phoned you.

### ₿ BTC address — the on-chain fan-out

| Widen step | Method | Yield |
|---|---|---|
| chain read | Blockstream | balance, tx history, counterparties |
| clustering | co-spend / change heuristics | other addresses of the **same wallet** |
| tagging | exchange / known-address DBs | link to a KYC'd entity |
| string search | the address in forums, donation/ransom pages | **handle / name** tied to it |

**feeds → username · name.** 🛡 **break:** fresh address per transaction, avoid
reuse, never post an identity-linked address publicly.

### 🧑 person name — a *discovery* seed (weak, but a launcher)

| Widen step | Method | Yield |
|---|---|---|
| social | `who is Jane Doe` → profiles | a **handle** (feeds → username) |
| employer | LinkedIn/company site | org → **domain** + email pattern (feeds → domain/email) |
| brokers | name + location → people-search | phone, address, relatives |
| records | news, registries, public filings | affiliations, dates |

**feeds → username · email · phone · domain.** 🛡 **break:** data-broker opt-outs,
minimise public social, keep legal name unlinked from handles.

### 🏢 company / org — the workforce fan-out

| Widen step | Method | Yield |
|---|---|---|
| domain map | org → its domain(s) | feeds → domain (whole chain above) |
| workforce | LinkedIn employees | **names** (feeds → name, ×N) |
| pattern | one leaked `@corp.com` | email format for everyone |
| breach | HIBP **keyless domain** lookup | exposed employee accounts on that domain |

**feeds → domain · name · email.** 🛡 **break:** domain hygiene + employee OSINT
awareness (public role/handle exposure is the workforce's shared attack surface).

### 🖼 image / photo — the visual fan-out

| Widen step | Method | Yield |
|---|---|---|
| reverse search | Yandex/Lens/Bing/TinEye | other sites using it → **profile / handle / name** |
| art matchers | SauceNAO · IQDB | source site, **creator handle** |
| EXIF/GPS | local Pillow read | **location**, device, timestamp, editing software |
| vision OCR | read watermark / visible handle / signature | a **username** |
| face (gated) | PimEyes/FaceCheck — manual, consent-only | other appearances of the same person |

**feeds → username · name · location.** 🛡 **break:** strip EXIF before posting,
don't reuse a profile photo across identities, mind visible handles/watermarks.

### 🧅 onion — index-only (never fetched here)

| Widen step | Method | Yield |
|---|---|---|
| clearnet index | Ahmia · Lyzem | *mentions / context only* — link kept as text |
| page artifacts (manual, in Tor) | PGP key · BTC address · reused handle | feeds → email · btc · username |

**feeds → (manual) btc · username · email.** 🛡 **break:** strict identity
separation — never reuse a handle, key, or address between clear and dark surfaces.

---

### Any → any: the full pivot matrix (free-for-all)

Every seed can reach every other type — directly, or by hopping through an
intermediate. Read a row as **"starting from this, here's how I reach each
column."** `·` = the seed itself; `— (via X)` = no direct jump, pivot through X
first. This is the whole board: any cell is a link, and chaining cells is how a
single scrap of data unravels an identity.

| FROM ↓ \ TO → | email | domain | IP | user | phone | btc | name | company | image |
|---|---|---|---|---|---|---|---|---|---|
| **email** | · alt-emails in breach | its `@domain` | — (via domain) | local-part = handle; breach | breach / recovery hint | — (via user) | Gravatar / breach / CV | its `@domain` → org | Gravatar avatar |
| **domain** | site scrape · Wayback · MX pattern | · crt.sh subdomains | DNS A record | linked social on site | contact page | donation addr on site | staff pages · WHOIS | WHOIS org | site assets (EXIF) |
| **IP** | — (via domain) | reverse-IP · cert SAN | · ASN neighbours | — (via domain) | — | — | ASN/WHOIS contact | hosting/ASN org | — |
| **user** | git commit · profile field · breach | linked site in bio | — (via domain) | · other handles; 22-site | breach · app find-by | tip addr in profile | profile real name | profile employer | profile avatar → reverse |
| **phone** | breach / combolist | — | — | messaging-app · reverse | · ported/linked #s | — | reverse lookup (Truecaller) | business listing | app profile photo |
| **btc** | forum post w/ addr | donation site | — | forum handle w/ addr | — | · co-spend cluster | exchange KYC tag | exchange/service tag | — |
| **name** | pattern via employer | employer domain | — (via domain) | social profiles | data brokers | — | · relatives (brokers) | employer | news / profile photo |
| **company** | pattern · HIBP domain breach | its domains | — (via domain) | employee handles | main line / dir | — (if crypto biz) | employee roster | · subsidiaries/partners | logo · staff photos |
| **image** | — (via user) | reverse → host sites | — | reverse → profile; OCR handle | — | OCR addr in image | reverse / face → identity | logo recognition | · near-duplicates |
| **onion** | PGP/contact on page | clearnet mirror link | — (never fetched) | reused handle | — | wallet on page | — | market operator | — |

*(onion column dropped — nothing pivots **to** an onion except a reused
handle/key you already hold; the onion **row** shows what a `.onion` page leaks,
all manual-in-Tor since Black Noir never fetches it.)*

**How to read it as an attacker:** pick your seed's row, jump to the richest cell
(usually **email** or **user**), then switch to *that* type's row and repeat. Two
or three hops turns one handle into name + email + phone + accounts.

**How to read it as a defender:** the columns that are reachable from the *most*
rows are your biggest exposure — **email, user, name** light up almost
everywhere. Harden those three identities (unique per context, 2FA, no reuse) and
you black out most of the matrix at once.

---

### The whole graph

```
image ─┐                                   ┌─▶ passwords
name ──┼─▶ handle ─▶ git/profile ─▶ email ─┼─▶ other emails
phone ─┘        │                    ▲     └─▶ phones ─▶ (loop)
                └─▶ breach ──────────┘
company ─▶ domain ─▶ IP ─▶ (reverse) ─▶ domain ─▶ site scrape ─▶ names/emails
btc ─▶ clustering ─▶ exchange tag ─▶ identity ─▶ handle/name ─▶ (loop)
```

Every arrow is a cuttable link. The cuts that appear across the **most** chains
are the highest-leverage: **no password reuse · 2FA everywhere · one identity
(handle/email/number/photo) per context.** Land those three and most seeds
dead-end no matter how hard they're enumerated.

---

## 14. Person investigations — phased & human-gated

For a **person** target the loop is a strict 5-phase, human-in-the-loop flow. It
never auto-pursues a specific individual — you pick the candidate before any deep
research runs.

**Run it (chat):**
```
python main.py --chat
you › search "王婧兒 Wong Jing Yi", student at Ko Lui Secondary School (secondary, not university), ig @wjy._.1203
```

**What happens, phase by phase:**
1. Input is typed into entities; your qualifier ("secondary student at Ko Lui
   Secondary School, NOT university") becomes a **hard constraint**. A pre-search
   summary prints before any query.
2. Queries are built **context-bound** (name + school + identifiers). With a
   constraint set, **no bare name-only queries** are emitted. The set is printed.
3. Engines run; each success/block/skip is logged with its reason.
4. Candidates are clustered and each tagged for **constraint fit**
   (`supports` / `unverified` / `contradicts` / `unknown`). Namesakes
   (university / PhD / overseas) stay separate and are **never** given the
   target's school tag.
5. The loop **stops** and asks you to choose.

**Select the target:**
```
you › /candidates          # review all candidates + constraint fit + evidence
you › /focus 2             # deep-dive ONLY candidate 2; rule the rest out
you › /dig                 # THEN let the agent dig candidate 2 autonomously,
                           #   round after round, until the lead runs dry
you › /dig                 # run again to push even deeper (skips done queries)
you › /refine <detail>     # (optional) add info to re-narrow before choosing
```
Only `/focus <n>` starts focused research on the chosen person; `/dig` then
unleashes the relentless autonomous loop on that one confirmed candidate.

> **`/dig` runs on your FREE AI keys.** The "propose the next query" brain is the
> LLM, auto-detected from `GOOGLE_API_KEY` → `NVIDIA_API_KEY` → `GROQ_API_KEY`
> (all free). With none set (or `--no-llm`) `/dig` falls back to weak heuristic
> queries. Because a long dig makes one LLM call **per round**, a single free
> tier can hit its rate limit mid-dig — so set **2–3 free keys**: the agent
> fails over between them and keeps digging instead of degrading to heuristic.

**`/max` vs `/dig` — breadth vs depth (they are not the same):**

| | `/max` (or `--max`) | `/dig` |
|---|---|---|
| Axis | **Breadth** — cast the widest net | **Depth** — exhaust ONE target |
| When | at search time, any target | AFTER `/focus` on a confirmed person |
| Does | all surfaces · every source · more queries per engine | agent self-directs many rounds, proposing its own next queries from what it finds |
| Stops | after the one wide sweep | when the lead saturates / goes dry / hits its step budget |
| Use it for | "don't miss a source" | "squeeze everything out of this person" |

Typical combo: `/max` the initial search to surface every candidate, `/focus`
the right one, then `/dig` (repeatedly) to go as deep as the public web allows.

**Reading the constraint tags:**
| Tag | Meaning |
|-----|---------|
| `supports` | evidence names this individual **and** fits your constraint |
| `unverified` | the context matched, but no result actually names this person |
| `contradicts` | a same-name university/PhD/overseas person — a namesake, not the target |
| `unknown` | no hard constraint given, or too little to judge |

**If nothing is found:** for a subject with no public footprint the report says
so plainly ("no personal data traces found") and stays **low** confidence — it
does not pad the findings with their school's public pages. Skipped/blocked
sources are always listed as limitations.

> Infra targets (domain / IP / company) skip the gate and run straight through —
> the human-selection stop is a person-target default.

---

## 15. Goal playbooks — maximize the combo (free-first)

Everything above is the *parts*. This section is the *assembly*: for the goals
people actually have, the exact **combo** that squeezes the most out of Black
Noir — starting with **$0** and noting where a cheap key lifts the ceiling.

**The combo formula.** Every good run is:

```
right SEED  ×  right SURFACE  ×  the keys that matter for it  ×  pivot in the right order
```

Get the *seed* wrong and nothing else saves you. The tool is only as strong as
the identifier you feed it (see §13 and the table below), so the whole game is:
**start from the strongest identifier you have, and pivot toward an even stronger
one before you go deep.**

### Free-tier setup (do this once — unlocks ~70% of the ceiling for $0)

Fill these free keys in `.env` before anything else. Ranked by impact:

```ini
SERPER_API_KEY=      # 1st: free 2,500 queries — the workhorse web engine
GROQ_API_KEY=        # 2nd: free — the planning/synthesis brain (or GOOGLE_API_KEY)
INTELX_API_KEY=      # 3rd: free dev key (~50 searches); comma-separate a few
GITHUB_TOKEN=        # 3rd: free forever — code search + git-email leaks
# XposedOrNot is keyless — already on, no key. Numverify/SauceNAO free-tier optional.
```

Effectiveness by seed **on the free tier** (what to feed it, best first):

| Seed you type | Free-tier power | Use it as your START when... |
|---|---|---|
| **email** | ~85% | you have an address — best for leaks *and* identity |
| **domain / company** | ~85% | investigating an org or its attack surface (keyless-rich) |
| **username / @handle** | ~80% | you have a handle — best for mapping someone's accounts |
| **btc address** | ~70% | tracing a wallet |
| **IP** | ~65% | infra recon (Shodan key lifts this) |
| **real name** | ~55% | *only with context* (employer/school/city) |
| **phone** | ~40% | self-audit / scam-vetting, **not** discovery |
| **onion** | ~35% | index mentions only |

> **Golden rule:** if your seed is a *name* or *phone*, your first job is to pivot
> UP to an *email* or *username*, then restart from that. Don't go deep on a weak
> seed.

---

### A. Playbook — "Find someone's background" (you don't know them)

**Combo:** strongest seed you have -> **public** surface, deep -> pivot to handle/email -> re-run.

1. **Have only a name?** Never search it bare — attach context, or it drowns in
   namesakes (this is exactly why the Lam Wing Kit run came back LOW).
   ```
   run.bat "\"Jane Chan\", software engineer at Acme, Hong Kong" --surface public --live
   ```
   Deep mode + context makes the tool emit *context-bound* queries only.
2. **Pick the real person.** In chat, don't let it profile everyone:
   ```
   /candidates          # review same-name candidates + constraint fit
   /focus 2             # deep-dive ONLY #2; the rest are ruled out as namesakes
   ```
3. **Pivot to a strong key.** The moment a result yields a **handle** or **email**,
   restart from THAT — it's the ~80–85% column:
   ```
   run.bat "@janedev" --surface all --live      # sweep 22 sites; GitHub git-email leak -> real email
   ```
4. **Depth from the strong key:** the recovered email/handle feeds breach lookups,
   git-commit email, profile fields -> name confirmed, other accounts, location.

**What good looks like:** you started at ~55% (name) and finished in the ~85%
band (email/handle). **Free is enough** here — Serper + GitHub + LLM carry it.
Paid adds little to *background* work specifically.

**Defender read:** unique handle per context + legal name unlinked from handles
snaps step 3 — the pivot that turns a name into everything.

---

### B. Playbook — "Is MY info leaked?" (self-audit — the easy problem)

**Combo:** your **email/domain** -> **darkweb** surface -> keyless breach stack -> manual app-privacy check.
You already know the identifiers, so no resolution is needed — this is the run
Black Noir is *most* reliable at.

```
python main.py --check-password --live          # is a password of mine burned? (only 5 hash chars leave)
run.bat "me@myemail.com"   --surface all --live  # XposedOrNot (KEYLESS) + IntelX + HIBP-domain
run.bat "mydomain.com"     --surface all --live  # keyless HIBP domain breaches
run.bat "@my_handle"       --surface all --live  # 22-site presence: where do I even have accounts?
```

- **`xposed` answers your email keylessly** — real breach hits with $0.
- Add free **`INTELX_API_KEY`** for paste/combolist coverage.
- Add **`HIBP_API_KEY`** (~$4.50/mo) later for the biggest corpus + per-account detail.

> **Worried a normal run missed something? Use MAX mode.** It throws *every*
> source, all surfaces, a deep multi-round loop, and the biggest query budget at
> the one target — the "leave nothing unchecked" run:
> ```
> python main.py --max "me@myemail.com" --live
> ```
> It costs more API credits (and burns a free IntelX quota fast), so it's the
> occasional deep-sweep, not the every-day default. Same idea in chat: `/max on`.

**Then, by hand (no crawler can reach these):**
- Save your own number -> open **WhatsApp / Signal / Telegram**: what name + photo
  show to a stranger who has your number? Lock it in each app's privacy settings.
- "Who can find me by number/email", 2FA method (app > SMS), followers-list
  privacy (the graph edge that makes you walkable from one known fact).

**What good looks like:** every breach naming you is listed with what leaked;
you rotate those passwords, enable 2FA, and tighten the app-visibility settings.
**Free tier fully covers this** — the paid keys only widen the net.

---

### C. Playbook — "Investigate a company / org"

**Combo:** **domain** seed -> **all** surfaces -> keyless infra stack (no keys needed) -> pivot to employees.

```
run.bat "acme.com" --surface all --all-sources --live
```

Fires the richest **keyless** toolset: RDAP/WHOIS, crt.sh (subdomains), passive
DNS, reverse-IP/hostsearch, Wayback, **and keyless HIBP domain breaches**. Then:

- subdomains/IPs -> feed an **IP** back in for service/CVE exposure (Shodan key
  lifts this from ~65% -> strong, but keyless InternetDB still runs);
- staff names on the site/LinkedIn -> feed each **name** (Playbook A);
- one leaked `@acme.com` -> the email *pattern* for everyone.

**What good looks like:** a map of the org's external surface + exposed employee
accounts. **Free tier is ~85% here** — infra recon barely needs paid keys.

---

### D. Playbook — "Vet a suspicious phone number / scam"

**Combo:** **phone** seed -> structure (keyless, offline) -> manual app + scam-DB pivots.
Phone is the tool's *weakest discovery* seed (~40%) — but for *vetting*, its
honest structural read + pivots are exactly right.

```
run.bat "+852 5550 0101" --live
```

Returns country, line type, and an explicit *"carrier not determinable"* where
number portability makes it so — and **never** names a subscriber (there's a test
enforcing that; no legit public directory exists). Then, by hand:

- save it -> check WhatsApp/Signal/Telegram profile;
- HK: check **Scameter** (cyberdefender.hk), call **18222** (ADCC) if it phoned you;
- if you also have a name, phrase it name-first so you target the *person*, not
  the number: `"Wong Jing Yi", ..., phone +852 ...` (number as *context*).

**What good looks like:** you know the region/line-type + scam reputation, not a
fabricated "owner." **Don't buy keys for this** — Numverify only adds carrier
detail, which portability already caveats.

---

### E. Playbook — "Map someone's accounts from a username"

**Combo:** **@handle** seed -> **all** surfaces -> 22-site sweep + GitHub git-email -> pivot to email.

```
run.bat "@nightowl" --surface all --live
```

- 22-site presence sweep (status-code confirmed) -> where the handle exists;
- **GitHub commit metadata often leaks a real, unguessed email** -> feeds Playbook B;
- IntelX/breach on the handle -> emails, phones, passwords;
- a link is only reported when the account *itself* declares the name (anonymous
  accounts are *supposed* to fail this — that's honesty, not a miss).

**What good looks like:** the handle's account graph + a recovered email to pivot
on. **Free tier ~80%**; free GitHub token is the key that matters here.

---

### F. Playbook — "Who is this / who drew this" (from an image)

**Combo:** drop file in `input/` -> reverse-image + EXIF + OCR -> pivot to handle/name.

```
run.bat "who is this" --live         # person -> face-engine links (manual, consent-gated)
run.bat "who drew this art" --live   # art -> SauceNAO/IQDB source + creator handle
```

- EXIF/GPS read locally (location/device/time) — free;
- OCR a visible watermark/handle -> a **username** (Playbook E);
- free **`SAUCENAO_API_KEY`** makes art-matching reliable; face engines are
  manual links by design (consent/authorization required).

**What good looks like:** other sites using the image -> a profile/handle/name to
restart from.

---

### Combo cheat-sheet

| Your goal | Best seed to start | Surface | Keys that matter | Pivot toward |
|---|---|---|---|---|
| Background on a stranger | name **+ context** -> handle/email | public -> all | Serper, LLM, GitHub (free) | handle -> email |
| Is my info leaked? | **email**, domain, handle | all | keyless (`xposed`) + free IntelX; HIBP later | rotate creds, app privacy |
| Investigate an org | **domain** | all | none needed (keyless) | subdomain -> IP -> employees |
| Vet a phone / scam | **phone** | public | none (Numverify optional) | app profile, scam DB |
| Map someone's accounts | **@handle** | all | GitHub (free) | git-email -> email |
| Identify from a photo | **image** file | public | SauceNAO (free) | OCR handle -> username |

**One habit beats every key:** *pivot up before you dig down.* A name or phone is
a launcher; get to an **email or username** and you've moved the whole run into
the tool's strongest band — for free.

---

## 16. Detective read, auto-discovery & agentic crawl

Search engines rank by popularity, so an obscure person's one real page (a
school award roster, a club member list) loses to their famous namesakes and to
their own institution's main pages. A snippet aggregator can't beat that ranking
— and snippets also *splice* non-adjacent lines, which is where false findings
("kin-ball", a phantom surname) come from. These three tools go past that by
reading actual pages, like a detective goes to the source instead of asking a
popularity engine.

All three are **read-only** (fetch + read public pages), opt-in, need `/live on`,
and are **universal** — the model reasons about any site and any persona; no
`if student` / hardcoded domains.

### `/read` — read the pages, extract grounded facts

```
you › search "Jane Doe", ... , member of the Riverside Rowing Club
you › /read
```

`/read` (no URL):
1. Reads every page the search already found that NAMES the target.
2. AUTO-DISCOVERS the institution in the context (a school, company, gallery,
   club — the model names it), resolves its domain (catching initialisms, e.g.
   `sbc` = St **B**onaventure **C**ollege), then MERGES three free listings of
   that site — its **sitemap.xml**, its **homepage links**, and the **Wayback
   Machine** index — and the model picks which to read.
3. Reads them all in full and extracts facts grounded in the text next to the
   name (an award, a class, a role) — never spliced across unrelated lines.

Results land in a **"Detective read — facts from full pages"** section of the
report, and every source is a scroll-to-name link.

### Paste a URL / `/read <url>` — agentic crawl from a page

```
you › https://www.example-school.edu/en/awards
```

Pasting a bare URL (or `/read <url>`) starts a **read-only agentic crawl** from
that page — the Mr-Red operator loop, minus any offensive action:

1. Read the page.
2. **Think** — the model looks at the links on it and reasons which lead toward
   pages that name the target (awards / roster / news / member / profile …).
3. Follow the promising ones, read them, repeat.
4. Stop at a **step budget** (default 12) so it always terminates.

Paste a deep page and it reads it + walks to related pages; paste the **homepage**
and it navigates INTO the site to find the target. It only ever *fetches and
reads* public pages — no forms, no login, no code, nothing non-public.

### When to use which

| Situation | Use |
|---|---|
| You know the exact page | paste the URL / `/read <url>` — crawls from it |
| You know the org but not the page | `/read` — auto-discovers + crawls the site |
| You want facts from what search already found | `/read` — reads the found pages too |
| Obscure target, search keeps missing the page | any of the above — reading beats ranking |

### Tuning (MAX mode bumps these too)

| Behaviour | Default | Note |
|---|---|---|
| Crawl step budget | 12 | pages the agent will visit from a URL |
| Named-page cap | 10 | pages kept for fact extraction |
| Discovery merge | sitemap + homepage + Wayback | free listings, deduped |

Honest limits: it fetches several pages (slower); it reads **raw-HTML** links, so
a pure-JavaScript nav menu can be invisible (most institutional sites are fine);
read-only means no members-only areas. For a page you already know, pasting the
URL never fails.

