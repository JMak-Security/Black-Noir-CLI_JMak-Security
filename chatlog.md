# Black Noir — development chatlog

Session date: **2026-08-26** · working copy: `Black Noir CLI_V1.0.0/`

A record of why Black Noir v1.0.0 returned nothing useful, what was actually
wrong, and every change made in response. Written so the reasoning survives —
the code comments say *what* a fix does, this says *why it exists*.

---

## 0. The starting point

The trigger was a report: `report_Alex_Marsh_20260826_155222.html`.

Instruction given to the tool:

```
"Alex Marsh" who is from AI Security Industry
```

What the report claimed:

| Metric | Value |
|---|---|
| Sources queried | 10 |
| Results | 45 |
| Entities | 11 |
| Confidence | **LOW** — "no direct digital footprint discovered" |

Top "findings": *Alex – Wikipedia*, *Alex Vance*, *Alex Stone*,
*Marsh's Deli*. The entity graph linked the target to a delicatessen, a
Telegram channel, and `20260817234951` — a Wayback timestamp misparsed as a
phone number.

The target was in fact trivially findable. Every failure below was
reproduced with a measurement before it was fixed.

---

## 1. Root causes (most upstream first)

### 1.1 The qualifier was deleted before any search ran

`parse_target`'s JSON schema was `{subject, subject_type, depth, is_question}`.
**No field for context**, and the prompt said *"Strip command words."* So
`"Alex Marsh" who is from AI Security Industry` became subject `Alex Marsh`, and
*AI Security Industry* was discarded.

It was not entirely lost — `inv.raw` kept it. But tracing every read: written
in `pipeline.py`, serialised in `models.py`, printed in `report_pdf.py`. The
planner prompt passed `TARGET: {inv.target}`, never `inv.raw`.
`_build_queries` used only `inv.target`.

**The qualifier was stored, printed in the PDF, and never used to search.**

Measured cost:

```
A  "Alex Marsh"              → Operational Due Diligence · a wedding site · IMDb
B  "Alex Marsh AI security"  → Alex Marsh – Independent AI Cybersecurity Researcher
```

One extra word. First result.

### 1.2 Quoted queries killed the only good source

Free-tier Serper rejects phrase quotes and operators:

```
'"Alex Marsh"'                 → 400 Query pattern not allowed for free accounts.
'Alex Marsh site:linkedin.com' → 400 Query pattern not allowed for free accounts.
'Alex Marsh'                   → 200  9 organic results
```

`_build_queries` hardcoded `f'"{t}"'` and `site:linkedin.com`. Worse,
`_collect_source` **broke out of the loop on the first failure**, so one bad
query retired the source for the whole run — deterministically, since the
first planner query was always the quoted one.

The connector then reported *"rate-limited, quota, or transient error"* —
a guess. It discarded `resp.text`, which contained the real cause.

> **Later correction:** re-measured hours later, the same key returned **200**
> for quotes, `site:` and `OR`. The restriction was real when measured and is
> not active now (plan change, or Serper's). The fix was therefore rewritten to
> be *adaptive* rather than assume the restriction — see §2.2.

### 1.3 Bing was returning content unrelated to the query

Five distinct queries, two user-agents, identical junk:

```
q='"Alex Marsh"'              → Alex – Wikipedia, Alex Vance, Alex Stone
q='Alex Marsh AI security'    → Alex – Wikipedia, Alex Vance, Alex Stone
q='Northwind AI SecConf'→ brick masonry contractors
q='AMarsh-Sec github'     → "The Influence of Breastfeeding Educational
                                Interventions" ×4
```

Not a UA problem (tested). The endpoint had stopped honouring the query at all.

### 1.4 Nothing checked whether a result was about the target

`correlate()` linked **every** regex match to the target as `co-occurs`, with
no test that the result mentioned the target. Hence the deli, the Telegram
handle, and the timestamp-as-phone-number.

### 1.5 No loop — so nothing could notice 1.1–1.4

Exactly three `_complete()` call sites existed:

| # | Call | When | Sees results? |
|---|---|---|---|
| 1 | `parse_target` | before any search | no |
| 2 | `plan` → queries | before any search | no |
| 3 | `synthesize` | after all searching | yes — but cannot act |

The `Agent` class had four methods: `parse_target`, `vision`, `plan`,
`synthesize`. **No method took results and decided to search again.** The
plan was frozen before the first HTTP request. `pivots.py` says it outright:
*"These are **manual** pivots: the operator opens them."*

The one feedback path — enrichment — was deterministic dispatch gated on
`weight >= 2`, where weight counts **regex repetition, not relevance**. The
Ahmia onion hit weight 6 because Ahmia's own footer repeats it, passed the
"corroborated" filter, got enriched, and produced the fake phone number. The
sole feedback mechanism amplified noise.

**Net: Black Noir could not distinguish "I found nothing" from "I searched
wrong."** A broken retriever and an absent target produced identical reports.

---

## 2. Phase 1 — retrieval fixes

### 2.1 Qualifier retained end-to-end
- `intent.py`: new `extract_context()`; quoted segments become the subject, the
  trailing clause becomes searchable context.
- `agent.py`: `parse_target` gained a `context` field, with a deterministic
  backstop if the model omits it.
- `_build_queries` rewritten: qualifier-first, operator-free.
- `_plan_llm` now receives the context and the original instruction.
- `models.py`: `Investigation.context`.

### 2.2 Serper made adaptive
Sends the query **as written**; falls back to plain keywords **only** on a 400
that actually refuses the syntax. Optimal on either plan. Reports the real
HTTP status and body on failure.

### 2.3 One bad query no longer retires a source
`skipped`/`planned` (configuration) stops the sweep; `blocked`/`error` (luck)
only stops it after 3 consecutive failures.

### 2.4 Bing removed, DuckDuckGo added as best-effort
DDG is intermittent — 200 with 10 clean results once, then `202` challenge on
6 consecutive attempts (GET and POST). Registered as opportunistic only;
Serper is the workhorse. A non-200 2xx is reported as `blocked`, never `empty`
— being refused is not evidence of absence.

### 2.5 Relevance gate on the entity graph
`is_about_target()` gates graph edges. A partial match requires the **surname**
plus context agreement, so *Alex Bell* and *Alex Doyle* no longer match
a search for *Alex Marsh*. Wayback-style timestamps rejected as phone numbers.

**Result:** Serper `blocked, 0 results, 1 query` → `ok, 30 results, 4 queries`.
Confidence LOW → medium. Measured **with `--no-llm`** — no AI involved.

---

## 3. Phase 2 — the candidate loop

The insight was the user's: a common name is *several different people*, and
one undifferentiated sweep cannot tell them apart or notice it searched badly.

New module `deepsearch.py`:

```
RECON      broad, context-qualified sweep — who might the target be?
CLUSTER    split results into DISTINCT identities, score each against context
PRIORITISE pursue the best, skip namesakes below the match floor
DEEP DIVE  per candidate: query from what is known about THAT candidate,
           judge each result against it, harvest attributes, re-query richer.
           Escalate when a round returns nothing; stop when saturated.
SYNTHESISE one dossier per candidate + an honest account of what was refused
```

Live result on the original target:

```
clustered into 5 candidate(s) [llm]
  [1] Alex Marsh – AI Security Researcher   match=1.00
  [2] Alex Marsh – Director of Software     match=0.10
  round 1: Alex Marsh Northwind AI research apprentice
         | Alex Marsh SecConf AI security
         | Alex Marsh SBC AI safety LLM red teaming
  saturated → confirmed, 12 evidence, 7 queries, confidence HIGH
```

The reflection step is real: in one run a candidate learned *"Forward Slope /
FSI San Diego"* in round 2 and re-queried with it in round 3.

Bounded by `QUERY_BUDGET=40`, `MAX_DEPTH=3`, `MAX_CANDIDATES=3`,
`DRY_ROUNDS=2`, `MIN_CONTEXT_MATCH=0.25` (all `BLACKNOIR_DEEP_*` overridable).
Default for person/name targets; `--deep-loop off` restores one-shot.

---

## 4. Overfitting audit

Asked directly whether the work was tuned to one target. Audited and measured.

**Ablation** — same parse task, three prompt variants, eight targets:

```
A  no examples at all      7/8
B  the Alex Marsh example   7/8
C  neutral examples        7/8
```

No measurable difference. The `--no-llm` path used **no prompt at all** and
still found the right person — the result came from search and clustering.

**But the audit found three genuine overfits**, all of which would have hurt
other searches:

| Bug | Symptom |
|---|---|
| `_CONTEXT_LEAD` written around one phrasing | `Liam O'Connor **of** Trinity College` kept the whole string; `Maria Rodriguez **working at** NASA` leaked "working" into the name |
| No org guard on connectives | `Massachusetts Institute **of** Technology` → subject "Massachusetts Institute" |
| `_FILLER` stripped `man/woman/person` case-insensitively | `Isle of **Man**` lost "Man" as a pronoun |

The last two were pre-existing. Fixed with a 34-word org-marker guard and
lowercase-only pronoun stripping. `TestGeneralization` uses only names
unrelated to anything developed against.

**Honest residue:** the constants above are judgement calls from one or two
runs, not measured optima. Tuning them properly needs a corpus of targets.

---

## 5. Later additions

### 5.1 Investigation memory (`memory.py`)
Confirmed identities persist and warm-start the next run on the same target.

Privacy-first, because it stores personal data about searched people:
- `--list-memory` prints everything held, in full
- `--forget "<target>"` / `--forget-all` — real deletion, verified (file drops
  to 38 bytes, no trace); **works even with `--memory off`**
- `--memory off` records nothing; `memory/` added to `.gitignore`
- Only *corroborated* identities stored — rejected namesakes would return as
  noise. Recalled data seeds queries and informs clustering; it **never counts
  as evidence**, so a stale memory costs queries but cannot fabricate findings.

### 5.2 Follow-up refinement (`/refine`)
Reuses candidates already found instead of re-running recon. The new detail is
authoritative — contradicting candidates are **excluded**, not down-ranked.
Never refines to zero. Works without an LLM via keyword re-ranking.

### 5.3 Clarifying questions
Taken from a Google AI-Mode log the user supplied. The pattern worth stealing
was not the narrowing — it was that the AI **asked** when `SBC` was ambiguous
instead of picking one of three unrelated people.

Triggers on: an unexpanded acronym in the qualifier (common ones like `AI`,
`LLM`, `CEO` exempt), a top candidate under 0.50, or a top-two gap under 0.20.
Works with no LLM via a deterministic fallback. Reproduced live:

```
context: 'SBC'
  [1] Rev. Dr. Patrick Novak / SBC connection   match=0.40
  [2] Kai Novak – Bendigo Bank               match=0.00
? Does 'SBC' stand for Singapore Bible College…?
```

Also: name variants (surname-first, initialled) tried in the last round —
records are often filed under a rendering you were not given. And open
questions now **cap synthesis confidence at medium**; a run once claimed
`confidence: high` while asking two questions about who the target was.

### 5.4 Image pipeline
Black Noir does **not** do face recognition, by design:
- vision prompt bans face→name inference
- SauceNAO/IQDB are art indexes, skipped for faces
- PimEyes/FaceCheck are manual links, never auto-uploaded

What it does instead: reads **marks**, and estimates **context**. Per the
user's argument — *"don't guess, but do give a priority list and confidence"* —
vision returns ranked leads, each citing visible evidence, with a
`how_to_verify`. A lead with no stated basis is dropped in the parser.

On a real photo:

```
identifiability: contextual
[0.50] Taken in an office/library in a Chinese-speaking region
       basis : Chinese characters on background signage
[0.30] Contemporary commercial interior, linear baffle ceiling
```

Zero leads naming a person. Estimation of *place*, not identity.

---

## 6. Bugs found in the tool's own honesty

A recurring pattern: **guessing a cause instead of reporting it.**

| Where | Was | Now |
|---|---|---|
| Serper connector | "rate-limited, quota, or transient error" | real HTTP status + body |
| `LLM._invoke` | swallowed every exception → bare `(vision call failed)` | names the exception |
| DDG `202` challenge | reported as `empty` | reported as `blocked` |
| Dead dark-web sources | counted as "queried" | `unavailable_reason` says why |
| Off-target onion results | shown as findings | hidden, with the count stated |

### The `person in photo.jpg` incident
Asked *"Who is the person in photo.jpg?"*, the tool searched the **filename** —
including `person in photo.jpg combolist` on the dark web — graded a `match=0.00`
candidate as `confirmed`, asked *"Who is the person depicted in the
self-portrait?"* (the user's own question, handed back), and saved it all to
memory. Five bugs:

1. placeholder guard missed `boy` and filenames → now catches ~25 person
   nouns, image nouns, leading adjectives, and any filename anywhere
2. vision's own *description* became the search qualifier → cleared
3. `match=0.00` graded `confirmed` → `_grade()` caps at `weak` below the floor
4. echo questions → filtered, and the prompt forbids them
5. placeholder saved to memory → `remember()` refuses placeholders

The unsearchable check now runs **before** planning, so no source list or
query set is printed for a search that never runs, and the failure is
actionable:

```
▮ Nothing to search
› what would make this searchable:
›   · a name, username or handle to start from
›   · legible text in the image (badge, signage, screen)
›   · where/when it was taken, or who they work or study with
```

---

## 7. Environment notes

- `openai` was **missing** from Python 3.14 despite being in
  `requirements.txt` — every run was silently heuristic-only. Installed.
- The `.bat` launchers prefer `dist/blacknoir-ai.exe` and only fall back to
  `python main.py`. A stale exe (built 15:49, before any fix) meant an hour of
  testing ran pre-fix code. **Rebuild after changing source**, or the launchers
  keep running the old binary.
- Backup of the pre-loop binary: `dist/blacknoir-ai.exe.pre-deepsearch.bak`

---

## 8. Test suite

**172 tests**, up from 87. New classes:

`TestContextRetention` · `TestQuerySanitizer` · `TestRelevanceGate` ·
`TestGeneralization` · `TestSerperOperatorFallback` · `TestDeepSearchLoop` ·
`TestSourceAvailability` · `TestReportCandidates` · `TestHeuristicAnchorMerge` ·
`TestMemory` · `TestRefine` · `TestVisionLeads` · `TestOffTargetFiltering` ·
`TestLLMErrorSurfacing` · `TestClarifyingQuestions` · `TestNameVariants` ·
`TestConfidenceCap` · `TestPlaceholderSubject` · `TestCandidateGrading` ·
`TestQuestionsNeverEchoTheAsk` · `TestMemoryRejectsPlaceholders`

Run: `python -m unittest discover -s tests`

---

## 9. Open items

- The deep-loop constants are unvalidated across a corpus of targets.
- The relevance gate treats the **last** name token as the surname — Western
  ordering. A *partial* match on a surname-first name (`Chan Siu Ming`) will not
  pass. Fails conservatively: a real result is left out of the graph rather
  than a wrong one asserted. Full-name matches work in any order.
- Vision OCR of small/blurred background signage is unreliable and is currently
  handed to the operator as a search string without a health warning.
- Heuristic (no-LLM) clustering merges profile anchors that co-occur in one
  result, but cannot read a job title — it will still over-split people whose
  profiles never appear on the same page.

---

# Session 2 — 2026-08-29 · from snippet-aggregator to detective-grade

Trigger: repeated runs on a low-profile target — a Hong Kong secondary student,
`Lam Wing Kit` (林永傑), one obscure school award page, a common name shared with
louder namesakes (a Highways engineer, mainland 林永傑s, US "Wing Lam"s). The
worst case for any OSINT tool, and it exposed every weakness at once.

## What was actually wrong (in the order we found it)

1. **The AI was silently dead.** Google's Gemini API is **geo-blocked in Hong
   Kong** (`400 FAILED_PRECONDITION — User location is not supported`). A 400 was
   treated as transient, so the tool retried Google twice on *every* LLM call,
   starving the working providers until synthesis fell back to a dumb summary —
   invisibly. Fix: recognise the geo-block as permanent and retire the provider
   on first hit (`llm._is_permanent`); flag any degraded run with an **AI
   DEGRADED** banner tied to what `agent.synthesize` actually did, not to whether
   a key existed.

2. **Fabrication from snippets.** A search snippet stitches non-adjacent page
   lines with `…`. `"Hong Kong Kin-ball … Lam Wing Kit, 4B"` made the model report
   the pupil as a kin-ball player — but on the real page he is under an *essay*
   award; kin-ball is a different section. Two guards: a **name-gate** (a page
   only becomes a person's evidence if it actually names them — applied to both
   the LLM clustering and the deep-dive judge, which previously trusted the
   model's `belongs` blindly), and **snippet-splice grounding** (an extracted
   activity/affiliation is kept only if it shares an ellipsis-fragment with the
   name). Also: a candidate that scores on context but has zero naming evidence
   is now flagged `⚠ inferred from context`, so a guessed label never reads as a
   finding.

3. **Hardcoded personas.** The recall fix started as a keyword hack
   (`student → search "awards"`) — which is just whack-a-mole; it has nothing for
   a retiree, an artist, a monk. Replaced with an **LLM adaptive-angle layer**
   (the model plans search angles from *who the target is*, for anyone) and an
   audit that removed the remaining static persona logic: `_HIGHER_ED_MARKERS`
   (assumed the target was never in higher-ed → misfired on a professor target)
   became a **symmetric** identity-vs-context rule; `_ROLE_SUFFIXES` (`dev/sec/
   ai`) assumed everyone was a techie → handle suffixes now come only from the
   person's context. Stale static that WAS a bug: the domain TLD list had no
   ccTLDs, so `sbc.edu.example` typed as a username — broadened.

4. **The real ceiling wasn't code.** Even fixed, the tool couldn't reliably
   *surface* his one page: Google ranks the loud namesakes and the school's main
   pages above an obscure `/awards` sub-page, and the free SERP plan strips
   `site:` operators. That is a search-ranking reality, not a bug. The answer is
   to stop asking the popularity engine and **read the source** — which Google's
   own AI Mode did (it opened the school pages and read them), finding far more.

## The capability that closed it — reading, not ranking

- **`deepread`** — fetch the pages that name the target and read them IN FULL,
  extracting facts grounded in the text beside the name. This alone removes the
  snippet-splice class of error (on the full page, kin-ball is visibly next to
  *other* pupils).
- **`discover`** — when the context names an institution, find its domain (from
  results, catching initialisms; else one search) and **merge three free listings
  of its site — sitemap.xml + homepage links + Wayback CDX** — then let the model
  pick what to read. The free equivalent of paid `site:` operators.
- **`agentcrawl`** — paste a URL (or `/read <url>` / `/crawl`): a **read-only**
  agent loop that reads a page, has the model reason which links lead toward the
  target, follows them, repeats, bounded by a step budget. The shape of an
  autonomous operator, but the only action is *fetch-and-read a public page* —
  no forms, no login, no code.
- UX: pasting a **bare URL** in chat now auto-reads it; evidence links carry a
  `#:~:text=` fragment that scrolls to the name.

## Provider

With Google geo-blocked, the fix (point 1) retires an unreachable provider fast,
and a working OpenAI-compatible provider is then configured in `.env` and placed
first in the auto-order so the multi-agent panel actually reasons. The specific
provider used during testing is an interim choice that lives only in `.env` — not
in the code — and is expected to change.

## Honest state at the end

- Common / findable targets: works out of the box (validated on a rich footprint
  — 19 grounded evidence items, recall intact, no fabrication).
- Obscure targets: the tool refuses to fabricate, contradicts every namesake
  symmetrically, and — with `/read` / a pasted URL — **reads the source** to
  recover the real record where ranking buries it.
- The residual limit (auto-*discovering* a page Google won't rank) is external;
  `/read <url>` or a SERP plan with operators is the answer, not more code.

Every change this session is a general mechanism — a grep for the target,
school, or `kin-ball` finds only comments-as-examples, never logic.
