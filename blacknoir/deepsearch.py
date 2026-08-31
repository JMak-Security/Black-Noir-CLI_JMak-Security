"""Iterative, candidate-driven deep search.

The one-shot pipeline asks a fixed set of questions once and summarises whatever
comes back. That cannot tell "I found nothing" from "I searched wrong", and for
a common name it cannot tell one person from another — every namesake lands in
the same undifferentiated pile.

This module runs the investigation as a loop instead:

    RECON      broad, context-qualified sweep — who *might* the target be?
    CLUSTER    split the raw results into DISTINCT candidate identities and
               score each against the user's disambiguating context
    PRIORITISE pursue the best-matching candidates, in order
    DEEP DIVE  per candidate, query using what is already known about THAT
               candidate; judge every result against that candidate; harvest new
               attributes; re-query with the richer picture. Escalate to more
               specific angles when a round returns nothing new, and stop when
               the candidate saturates.
    SYNTHESISE one dossier per candidate, plus an honest account of what was
               searched and what was merely refused.

Every stage degrades: without an LLM the clustering falls back to profile-URL
identity anchors and the deep dive to attribute-templated queries, so the loop
still runs (and still beats one-shot) on a keyless, model-less install.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Callable, Optional

from .config import (MAX_RESULTS_PER_SOURCE, REGISTRY, Source,  # noqa: F401
                     has_advanced_operators, sanitize_query)
from .connectors import run_source
from .entities import is_about_target
from .models import SearchResult, SourceRun

# ---- budgets ---------------------------------------------------------------
# Every one of these is a hard ceiling: the loop must always terminate, and it
# must never quietly spend an unbounded number of API calls.
MAX_CANDIDATES = int(os.environ.get("BLACKNOIR_DEEP_MAX_CANDIDATES", "3"))
MAX_DEPTH = int(os.environ.get("BLACKNOIR_DEEP_MAX_DEPTH", "3"))
QUERY_BUDGET = int(os.environ.get("BLACKNOIR_DEEP_QUERY_BUDGET", "40"))
RECON_QUERIES = int(os.environ.get("BLACKNOIR_DEEP_RECON_QUERIES", "4"))
QUERIES_PER_ROUND = int(os.environ.get("BLACKNOIR_DEEP_ROUND_QUERIES", "3"))
# When the user supplied a disambiguating context, candidates scoring below
# this are namesakes, not the target — profiling them burns the query budget on
# strangers. The best candidate is always pursued regardless, so a run can
# never come back empty just because every score was low.
MIN_CONTEXT_MATCH = float(os.environ.get("BLACKNOIR_DEEP_MIN_MATCH", "0.25"))
# Consecutive rounds yielding nothing new before a candidate is declared dry.
DRY_ROUNDS = 2
# How many `site:`-scoped dork queries the recon sweep adds. 0 disables them.
WALL_DORKS = int(os.environ.get("BLACKNOIR_DEEP_WALL_DORKS", "6"))

# Platforms that refuse an unauthenticated automated fetch but whose public
# pages Google HAS indexed. We cannot read instagram.com directly — a crawler
# gets a login wall, and evading that is both an arms race and against the
# no-evasion policy in guardrails.py. But we can ask Google what it already
# saw there, which needs no evasion, no session and no new dependency: it is
# an ordinary query to an API we already pay for.
#
# This is the single biggest reach gain available to the tool, because these
# are exactly the platforms a person's footprint actually lives on and exactly
# the ones every direct-fetch connector is locked out of.
_WALLED_SITES = (
    "linkedin.com/in", "instagram.com", "facebook.com", "x.com",
    "tiktok.com", "threads.net", "youtube.com",
)
# Document types that leak names in bulk: membership lists, class rosters,
# committee minutes, prize-giving programmes. For a self-audit these are the
# highest-value dorks — nobody remembers being named in a PDF.
_LEAK_FILETYPES = ("pdf", "xlsx", "docx")

_PROFILE_PATTERNS = (
    re.compile(r"linkedin\.com/in/([A-Za-z0-9\-_%]+)", re.I),
    re.compile(r"github\.com/([A-Za-z0-9\-_]+)", re.I),
    re.compile(r"(?:twitter|x)\.com/([A-Za-z0-9_]+)", re.I),
    re.compile(r"instagram\.com/([A-Za-z0-9_.]+)", re.I),
)


@dataclass
class Candidate:
    """One distinct real person/entity that shares the target's name."""
    label: str
    role: str = ""
    org: str = ""
    location: str = ""
    context_match: float = 0.0
    why: str = ""
    # accumulated identifiers discovered across rounds; these drive the next
    # round's queries, which is what makes the search go *deeper* rather than
    # merely repeat itself.
    attributes: dict = field(default_factory=dict)
    evidence: list = field(default_factory=list)      # list[SearchResult]
    queries_run: list = field(default_factory=list)
    rounds: int = 0
    outcome: str = "pending"    # confirmed | weak | dry | skipped

    def anchor_terms(self) -> list[str]:
        """The distinguishing terms to put in this candidate's queries."""
        terms = [t for t in (self.org, self.role, self.location) if t]
        for key in ("orgs", "handles", "usernames", "affiliations", "topics"):
            terms.extend(self.attributes.get(key, []))
        # short, high-signal terms only — long phrases hurt recall
        out, seen = [], set()
        for t in terms:
            t = re.sub(r"\s+", " ", str(t)).strip()
            if 2 <= len(t) <= 40 and t.lower() not in seen:
                seen.add(t.lower())
                out.append(t)
        return out

    def to_dict(self) -> dict:
        d = asdict(self)
        d["evidence"] = [r.to_dict() if hasattr(r, "to_dict") else r
                         for r in self.evidence]
        return d


@dataclass
class DeepSearchState:
    target: str
    context: str = ""
    aliases: list = field(default_factory=list)   # other names for the target
    candidates: list = field(default_factory=list)     # list[Candidate]
    recon_results: list = field(default_factory=list)  # list[SearchResult]
    # Results that came specifically from the `site:`/`filetype:` pass, kept
    # separate so the report can say which findings came from behind a wall.
    dork_results: list = field(default_factory=list)   # list[SearchResult]
    # None = the dork pass did not run; False = it ran but no engine honoured
    # the operators, so the walled platforms were NOT actually searched.
    dork_honoured: Optional[bool] = None
    # Every query actually issued, so reflection can avoid repeating itself and
    # the report can show what was asked, not just what came back.
    tried_queries: list = field(default_factory=list)
    reflected: bool = False
    # How the haul splits: results naming the individual vs results that only
    # match the org/qualifier. Reported so the imbalance is a stated number
    # rather than something an operator has to infer from the evidence list.
    person_results: int = 0
    context_results: int = 0
    # Whether a recon sweep ran in THIS invocation. A /focus or /refine run
    # continues from a previous run's candidates and never sweeps again, so an
    # empty `recon_results` there means "not re-run", not "found nothing" — and
    # the report must not render those the same way.
    recon_ran: bool = False
    queries_spent: int = 0
    llm_calls: int = 0
    rounds_total: int = 0
    notes: list = field(default_factory=list)
    mode: str = "heuristic"
    # How many models actually answered a search fan-out. 1 means the panel was
    # off or only the primary replied; >1 means candidates and evidence were
    # voted rather than taken from a single model's opinion.
    panel_models: int = 1
    # Per-engine outcome for the recon sweep, keyed by source. The loop merges
    # every engine into one result pile, so without this a source that was
    # refused on every query vanishes from the report entirely — and a silently
    # dead engine reads as "this person has no footprint".
    source_health: dict = field(default_factory=dict)
    # Questions the search cannot answer for itself. Asking beats guessing:
    # one word from the operator ("SBC is a school") can collapse a dozen
    # namesakes to one, which no amount of extra querying will do.
    questions: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target, "context": self.context,
            "aliases": self.aliases, "mode": self.mode,
            "panel_models": self.panel_models,
            "queries_spent": self.queries_spent, "llm_calls": self.llm_calls,
            "rounds_total": self.rounds_total, "notes": self.notes,
            "questions": self.questions,
            "candidates": [c.to_dict() for c in self.candidates],
        }


# ---- helpers ---------------------------------------------------------------

def _log(cb: Optional[Callable[[str], None]], msg: str) -> None:
    if cb:
        cb(msg)


def _json_from(out: str):
    """Parse the JSON object in a model response, or None.

    Delegates to the shared extractor so the deep loop tolerates the same
    reasoning-model narration the target parser does.
    """
    from .llm import json_from_model
    return json_from_model(out)


def _result_key(r: SearchResult) -> str:
    return (r.url or r.title or "").strip().lower()


def _corpus(results: list, limit: int = 40) -> str:
    return "\n".join(
        f"[{i}] {r.title[:120]}\n    {r.url[:110]}\n    {r.snippet[:180]}"
        for i, r in enumerate(results[:limit]))


def _profile_anchors(r: SearchResult) -> list[str]:
    """Identity anchors (profile handles) present in a result's URL."""
    out = []
    for pat in _PROFILE_PATTERNS:
        for m in pat.findall(r.url or ""):
            if m.lower() not in ("in", "company", "posts", "search", "p"):
                out.append(m)
    return out


def _public_sources(surfaces: list, only: Optional[list]) -> list:
    # Only real web engines belong in the NL deep loop; public infra/archive
    # sources (crt.sh, Wayback) are domain-keyed and run in the fixed sweep.
    srcs = [s for s in REGISTRY.values()
            if s.surface in surfaces and s.surface == "public" and s.available
            and s.kind in ("engine", "serp")]
    if only:
        srcs = [s for s in srcs if s.key in only]
    # engines with a real query path first (serp API before best-effort scrape)
    return sorted(srcs, key=lambda s: 0 if s.kind == "serp" else 1)


def _health(state: DeepSearchState, src, status: str, detail: str = "") -> None:
    """Record one engine's outcome for a query, keeping the worst news.

    'ok' anywhere means the engine works; otherwise the first refusal is kept
    with its reason, so the report can say *why* an engine contributed nothing.
    """
    h = state.source_health.setdefault(
        src.key, {"label": src.label, "status": status, "detail": detail,
                  "queries": 0, "ok": 0})
    h["queries"] += 1
    if status == "ok":
        h["ok"] += 1
        h["status"] = "ok"
        h["detail"] = ""
    elif h["status"] != "ok":
        h["status"] = status
        h["detail"] = h["detail"] or detail


def _run_queries(sources: list, queries: list, fetcher, state: DeepSearchState,
                 seen: set, log=None) -> list:
    """Run each query against each source, returning only unseen results.

    Respects the global query budget; every query consumed is counted even when
    the source refuses it, so a blocked engine cannot spin the loop forever.
    """
    fresh: list = []
    for q in queries:
        q = (q or "").strip()
        if not q:
            continue
        if state.queries_spent >= QUERY_BUDGET:
            state.notes.append(
                f"query budget ({QUERY_BUDGET}) exhausted — search truncated")
            _log(log, f"budget exhausted after {state.queries_spent} queries")
            break
        state.queries_spent += 1
        if q not in state.tried_queries:
            state.tried_queries.append(q)
        for src in sources:
            try:
                run = run_source(src, q, fetcher)
            except Exception as exc:                      # never break the loop
                state.notes.append(f"{src.key} raised {type(exc).__name__}")
                _health(state, src, "error", f"{type(exc).__name__}: {exc}"[:90])
                continue
            _health(state, src, run.status, run.detail)
            if run.status not in ("ok", "empty"):
                continue
            for r in run.results:
                k = _result_key(r)
                if k and k not in seen:
                    seen.add(k)
                    fresh.append(r)
    return fresh


# ---- phase 1: recon --------------------------------------------------------

def _recon_queries(target: str, context: str, ttype: str,
                   prior: Optional[list] = None,
                   aliases: Optional[list] = None) -> list:
    """Broad, operator-free, context-qualified opening sweep.

    Terms recalled from a previous confirmed run lead, because a known employer
    or handle finds the right person immediately instead of after two rounds.
    An alternate name for the target leads too: a romanized name shares its
    spelling with hundreds of strangers, while the native-script or legal form
    the user supplied often resolves the identity in a single query.
    """
    ctx = (context or "").strip()
    base = f"{target} {ctx}".strip() if ctx else target
    qs = []
    for term in (prior or [])[:2]:              # warm start from memory
        qs.append(f"{target} {term}")
    alts = [a for a in (aliases or []) if a][:2]
    for alt in alts:
        # The alias goes out ALONE first, before any context-qualified form.
        # Appending the org to every query is what made a sweep return the
        # school and never the pupil: the engine is given two subjects and
        # ranks the one with thousands of pages. A native-script name does not
        # need the org to disambiguate — it is already far more unique than the
        # romanisation, so it is the one query that is both person-focused and
        # low-namesake-risk. Measured: 10 of 10 evidence items were school
        # pages when every query carried the school.
        qs.append(alt)
        if ctx:
            qs.append(f"{alt} {ctx}".strip())
    qs.append(base)
    # No bare name-only probe when a hard constraint is supplied: it only pulls
    # same-name namesakes the operator's constraint is meant to exclude. Every
    # recon query stays context-qualified.
    # Naming the PLATFORM in the query is what surfaces an account whose handle
    # does not resemble the name. Measured, on a real case: "Alex Marsh",
    # "Alex Marsh LinkedIn" and "Alex Marsh profile" all return a DIFFERENT Alex
    # Marsh, while "Alex Marsh github" returns github.com/AMarsh-Sec on the
    # first result — a handle no permutation of the name would ever generate.
    #
    # "github" used to be appended for username/handle targets only, so the one
    # query that finds a person's code presence was never sent for a person
    # target. It also sat past the cap, so it never ran there either.
    # Deterministic FLOOR only: generic broadening probes. The persona-specific
    # angles (a pupil's awards page, a retiree's obituary, an artist's gallery)
    # come from the LLM adaptive layer in recon(), which works for ANY kind of
    # person — no hardcoded 'student vs professional' category detection here.
    platform_suffixes = ["LinkedIn", "github", "profile"]
    if ttype in ("username", "handle"):
        platform_suffixes = ["github", "LinkedIn", "profile"]
    for suffix in platform_suffixes + ["company"]:
        qs.append(f"{base} {suffix}")
    # Alternate names EXTEND the sweep rather than displacing the broadening
    # probes: they are extra angles on the same person, and squeezing out the
    # "<name> LinkedIn"-style queries to make room would trade recall for them
    # instead of adding to it. The loop's overall QUERY_BUDGET still applies.
    # Alias-alone queries are extra angles on the PERSON, so they extend the
    # budget rather than displacing the broadening probes.
    cap = RECON_QUERIES + (2 * len(alts) if ctx else len(alts))
    return [sanitize_query(q) for q in dict.fromkeys(qs) if q][:cap]


def org_vs_person(results: list, state: DeepSearchState) -> tuple:
    """(about_person, about_context_only) counts for a result set.

    Makes the imbalance visible instead of leaving an operator to notice that
    a 'successful' sweep was mostly the employer's website. A run that returns
    fifty pages about a school and none about the pupil has not half-succeeded;
    it has failed in a way that looks productive.
    """
    from .entities import (_GENERIC_CONTEXT, _significant_tokens,
                           _token_present)
    ctx_tokens = [c for c in _significant_tokens(state.context)
                  if c not in _GENERIC_CONTEXT]
    person = ctx_only = 0
    for r in results or []:
        blob = f"{r.title} {r.snippet} {getattr(r, 'url', '')}"
        if is_about_target(blob, state.target, "", state.aliases):
            person += 1
        elif ctx_tokens and any(_token_present(c, blob.lower())
                                for c in ctx_tokens):
            ctx_only += 1
    return person, ctx_only


REFLECT_QUERIES = int(os.environ.get("BLACKNOIR_DEEP_REFLECT_QUERIES", "4"))


def _names_target_in_context(r, state: DeepSearchState) -> bool:
    """Does this ONE result tie the target's name to their context?

    Two weaker questions are easy to confuse with this one, and both give the
    wrong answer for a common name:
      * "does it name the target?" — every namesake does;
      * "does it match the context?" — every page about the school does.
    Only a result satisfying both is evidence about this individual. When no
    context was supplied, naming the target is all there is to ask.
    """
    from .entities import (_GENERIC_CONTEXT, _significant_tokens,
                           _token_present)
    blob = f"{r.title} {r.snippet} {getattr(r, 'url', '')}"
    if not is_about_target(blob, state.target, "", state.aliases):
        return False
    if not state.context:
        return True
    ctx_tokens = [c for c in _significant_tokens(state.context)
                  if c not in _GENERIC_CONTEXT]
    if not ctx_tokens:
        return True
    low = blob.lower()
    return any(_token_present(c, low) for c in ctx_tokens)


def _observed_domains(results: list, limit: int = 4) -> list:
    """Hosts that recur in the results, most frequent first.

    When a sweep for a person returns their school's own website, the site is
    telling us where to look next: the org publishes pages, and the person may
    be named on one of them. Turning an observed host into
    `site:<host> "<name>"` is the highest-yield reformulation available, and it
    needs no model — it is derived from what actually came back.
    """
    counts: dict = {}
    for r in results or []:
        url = getattr(r, "url", "") or ""
        if "//" not in url:
            continue
        host = url.split("//", 1)[1].split("/", 1)[0].lower().lstrip("www.")
        if not host or host.endswith((".google.com", ".bing.com")):
            continue
        counts[host] = counts.get(host, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: -kv[1])
    return [h for h, _ in ranked[:limit]]


def _heuristic_reflection(state: DeepSearchState, results: list) -> list:
    """Model-free reformulation from what the last round actually returned."""
    qs: list = []
    name = state.target
    for host in _observed_domains(results):
        qs.append(f'site:{host} "{name}"')
        for alt in state.aliases[:1]:
            qs.append(f'site:{host} "{alt}"')
    # An alias that has not been tried on its own is the strongest untried
    # angle: a native-script name is far more unique than its romanisation.
    for alt in state.aliases[:2]:
        qs.append(f'"{alt}"')
    return list(dict.fromkeys(qs))


def reflect_and_retry(state: DeepSearchState, ttype: str, sources: list,
                      fetcher, seen: set, agent, results: list,
                      log=None) -> list:
    """Diagnose why a sweep missed, then search again on the diagnosis.

    The loop previously planned every query up front, blind, and never revised
    them after seeing what came back. That is the whole gap against a hosted
    search agent: it is not a better index — Serper IS Google — it is that a
    human-like searcher reads the first page of results, notices they are the
    wrong person, and changes the query. Measured on a real case, "Alex Marsh"
    returns a different Alex Marsh while "Alex Marsh github" returns the right
    one on result #1. Nothing here could ever have made that second move.

    Trigger: not a low result COUNT, but that no result names the person. Ten
    pages about the right school and the wrong pupils is a failed sweep even
    though it looks productive.
    """
    # The trigger must be "nothing found THIS person", not "nothing found
    # ANYONE with this name". Measured on a real run: a sweep returned a
    # University of London namesake (names the target: yes) and ten pages about
    # the right school (context: yes) — and not one page that was both. Asking
    # only "did anything name the target?" saw the namesake and concluded the
    # sweep had succeeded, so the reflection never ran on precisely the case it
    # exists for. A result must carry the name AND a discriminating context
    # term to count as having found the person.
    hit = [r for r in results
           if _names_target_in_context(r, state)]
    if hit:
        return []                       # the sweep found the person; no retry
    _log(log, f"reflection: {len(results)} result(s), none tie the name to the "
              f"context — diagnosing and re-querying")

    queries = _heuristic_reflection(state, results)

    if agent and getattr(agent, "enabled", False):
        sample = [{"title": r.title[:120], "snippet": (r.snippet or "")[:140],
                   "url": (getattr(r, "url", "") or "")[:110]}
                  for r in results[:18]]
        prompt = (
            f"TARGET: {state.target}\n"
            + (f"ALIASES: {', '.join(state.aliases)}\n" if state.aliases else "")
            + (f"CONTEXT: {state.context}\n" if state.context else "")
            + f"QUERIES ALREADY TRIED (do not repeat): "
              f"{json.dumps(state.tried_queries[-14:])}\n"
              f"RESULTS THEY RETURNED: {json.dumps(sample)[:3500]}\n\n"
              "NONE of these results name the target. Diagnose why, then fix "
              "the query. Classify the failure as exactly one of: "
              "'namesakes' (right name, wrong people), 'context_only' (pages "
              "about the org/school but not the person), 'off_topic' (unrelated "
              "to both), or 'absent' (the target may have no indexed footprint)."
              "\n\nThen write queries that would separate the target from what "
              "came back. Use what you SEE in the results: if an organisation's "
              "own site appears, search that site for the name; if the wrong "
              "people share a profession or city, add a term only the real "
              "target would carry; if a native-script alias exists, use it "
              "alone. Name a platform (github, instagram, linkedin, facebook) "
              "when the target type makes one likely.\n"
              "If the results consistently spell a name or organisation "
              "DIFFERENTLY from the CONTEXT above, report it in "
              "'context_mismatch' as {\"given\":\"...\",\"observed\":\"...\"}. "
              "Do NOT silently substitute your version into the queries: the "
              "operator may be right and you may be wrong, and a query quietly "
              "rewritten to a different subject searches for the wrong person "
              "without anyone noticing. Report it; the operator decides.\n"
              'Respond ONLY as JSON: {"failure":"...","reason":"one sentence",'
              '"context_mismatch":null,"queries":["...","..."]}. Queries must '
              "be plain search strings, different from the ones already tried.")
        datas = agent.fanout_json(
            "You are a search strategist. Output strict JSON only.",
            prompt, 700, label="reflecting")
        state.llm_calls += max(1, getattr(agent, "panel_n", 1))
        for d in datas or []:
            if d.get("failure"):
                note = f"reflection: {d['failure']} — {str(d.get('reason',''))[:110]}"
                if note not in state.notes:
                    state.notes.append(note)
                    _log(log, f"  {note}")
            # A disagreement with the operator's own input is ASKED, never
            # applied. The models here spotted a mistyped school name and were
            # right — but a model that is confidently wrong would otherwise
            # redirect the whole search at a different subject silently, and
            # the operator would read the result as being about their target.
            # Surfacing it costs one question; getting it wrong costs the run.
            mm = d.get("context_mismatch")
            if isinstance(mm, dict) and mm.get("given") and mm.get("observed"):
                given, observed = str(mm["given"])[:60], str(mm["observed"])[:60]
                if given.lower() != observed.lower():
                    q = (f"The results consistently say {observed!r} where you "
                         f"gave {given!r}. If {observed!r} is correct, re-run "
                         f"with it — the current context may be excluding the "
                         f"right pages. If you are sure, ignore this.")
                    if q not in state.questions:
                        state.questions.append(q)
                        _log(log, f"  ? context mismatch: given {given!r}, "
                                  f"results say {observed!r}")
            for q in (d.get("queries") or []):
                if isinstance(q, str) and q.strip():
                    queries.append(q.strip())

    tried = {q.lower() for q in state.tried_queries}
    fresh_qs = [q for q in dict.fromkeys(queries)
                if q.lower() not in tried][:REFLECT_QUERIES]
    if not fresh_qs:
        state.notes.append("reflection produced no query the sweep had not "
                           "already tried")
        return []
    _log(log, "  retry: " + " | ".join(q[:44] for q in fresh_qs))

    # Operator-bearing reformulations only make sense on engines that honour
    # them; everything else goes to the full source list.
    plain = [q for q in fresh_qs if not has_advanced_operators(q)]
    dorky = [q for q in fresh_qs if has_advanced_operators(q)]
    out: list = []
    if plain:
        out += _run_queries(sources, plain, fetcher, state, seen, log)
    if dorky:
        op_sources = [s for s in sources if s.kind in _OPERATOR_KINDS]
        for q in dorky:
            got = _run_queries(op_sources or sources, [q], fetcher, state,
                               seen, log)
            if _dork_was_honoured(q, got) or not _dork_constraint(q)[0]:
                out += got
    state.reflected = True
    _log(log, f"  reflection recovered {len(out)} additional result(s)")
    return out


def _wall_dorks(target: str, context: str, ttype: str,
                aliases: Optional[list] = None, limit: int = WALL_DORKS) -> list:
    """`site:`/`filetype:` queries aimed at surfaces we cannot fetch directly.

    Every other query this module builds is run through `sanitize_query`, which
    strips exactly the operators that make a dork a dork. That is correct for
    the broad sweep (free SERP tiers reject operators outright) but it meant the
    tool had NO way to reach a login-walled platform, even though the engine it
    already queries has those pages indexed.

    These queries deliberately keep their operators. `_run_serper` retries
    without them if the plan refuses the syntax, so a restricted key degrades to
    plain keywords instead of failing.
    """
    if limit <= 0 or not (target or "").strip():
        return []
    names = [target] + [a for a in (aliases or []) if a][:1]
    ctx = (context or "").strip()
    suffix = f" {ctx}" if ctx else ""

    social: list[str] = []
    # A person's footprint lives on the walled platforms; infra targets do not
    # have one, so they get the document dorks only.
    if ttype in _PERSON_TYPES or ttype in ("username", "handle"):
        social = [f'site:{s} "{names[0]}"{suffix}' for s in _WALLED_SITES]
        # An alternate/native-script name is often the ONLY form a local
        # document or profile uses, so give it a pass of its own.
        if len(names) > 1:
            social.insert(1, f'site:{_WALLED_SITES[0]} "{names[1]}"')
    docs = [f'filetype:{ft} "{names[0]}"{suffix}' for ft in _LEAK_FILETYPES]

    # Split the budget rather than letting one category eat it. Truncating a
    # single concatenated list starved the filetype dorks completely for person
    # targets — and those are the ones that surface the rosters and programmes
    # nobody remembers being named in, which is the whole point for a self-audit.
    doc_slots = min(len(docs), max(1, limit // 3)) if social else min(len(docs), limit)
    qs = social[:max(0, limit - doc_slots)] + docs[:doc_slots]
    return list(dict.fromkeys(qs))[:limit]


# Sources that MIGHT honour a search operator. Sending `site:` to an onion
# index or a breach API just burns a query for a guaranteed miss. Note "might":
# whether an engine actually obeys the operator is verified per-result below,
# because several accept the query and quietly ignore the operator.
_OPERATOR_KINDS = ("serp", "engine")

# How many dork queries may come back unhonoured before the pass gives up.
_DORK_PATIENCE = 2


def _dork_constraint(query: str) -> tuple:
    """('site', 'instagram.com') / ('filetype', 'pdf') / ('', '') for a dork."""
    m = re.search(r"\bsite:(\S+)", query, re.I)
    if m:
        return "site", m.group(1).lower().rstrip('"')
    m = re.search(r"\bfiletype:(\S+)", query, re.I)
    if m:
        return "filetype", m.group(1).lower().rstrip('"')
    return "", ""


def _dork_was_honoured(query: str, results: list) -> bool:
    """True when the engine actually applied the operator we sent.

    Measured, not assumed. Three separate engines accept a `site:` query and
    silently ignore the operator: a free-tier SERP API strips it before
    searching, an RSS SERP endpoint drops it, and results come back looking
    perfectly well-formed — just answering a different question than the one
    asked. Pooling those into recon would double-count the plain sweep and
    present it as coverage of LinkedIn/Instagram that never happened.

    Same principle as `_looks_like_decoy` in connectors: a result set that does
    not satisfy the constraint it was given is not a finding.
    """
    kind, value = _dork_constraint(query)
    if not kind or not results:
        return False
    if kind == "site":
        host_part = value.split("/")[0]
        return any(host_part in (r.url or "").lower() for r in results)
    return any((r.url or "").lower().split("?")[0].endswith("." + value)
               for r in results)


def _llm_angle_queries(state: DeepSearchState, agent, log=None) -> list:
    """Let the model plan search angles from WHO the target is — universally.

    Hardcoding 'student -> school awards, professional -> LinkedIn' is a losing
    game: it has nothing for a retiree, an artist, a monk, a homemaker. Instead,
    the model reasons about the person from the context and proposes the angles
    most likely to surface pages that NAME them — school achievements for a
    pupil, obituaries/community notices for an elderly person, exhibitions for an
    artist, registries for a business owner. No category list; it adapts to
    anyone. Returns [] silently when no model is available (the deterministic
    sweep still runs), so this only ever ADDS recall, never removes it.
    """
    aliases = [a for a in (state.aliases or []) if a]
    prompt = (
        f'TARGET NAME: "{state.target}"\n'
        f'CONTEXT (who they are): "{state.context}"\n'
        + (f'ALSO KNOWN AS: {", ".join(aliases)}\n' if aliases else "")
        + "Plan an OSINT search to find THIS specific person's public "
        "footprint. Reason about who they are from the context and where a "
        "person like that actually appears online — e.g. a school pupil on "
        "award/achievement/prize-day pages; an elderly person in obituaries, "
        "community notices, local news; an artist in galleries and exhibition "
        "listings; a business owner in company/registry records; a clergy "
        "member on parish/temple pages; a homemaker perhaps only in family or "
        "local mentions. Propose the 4-6 plain-keyword queries most likely to "
        "return pages that NAME this person, each including the name (or the "
        "native-script alias if given).\n"
        "RULES: no quotes, no site:/filetype: operators.\n"
        'Respond ONLY as JSON: {"queries":["...","..."]}')
    datas = agent.fanout_json(
        "You are an OSINT search planner adapting to any kind of person. "
        "Strict JSON only.", prompt, 500, label="angles")
    state.llm_calls += max(1, getattr(agent, "panel_n", 1))
    out, seen_q = [], set()
    for d in (datas or []):
        for q in (d.get("queries") or []):
            if not isinstance(q, str):
                continue
            q = sanitize_query(q.strip())
            if q and q.lower() not in seen_q:
                seen_q.add(q.lower())
                out.append(q)
    if out:
        _log(log, f"  adaptive angles: {len(out)} model-planned quer(ies) "
                  f"(tailored to the person, not a fixed category)")
    return out[:6]


def recon(state: DeepSearchState, ttype: str, sources: list, fetcher,
          seen: set, log=None, prior_terms: Optional[list] = None,
          agent=None) -> list:
    qs = _recon_queries(state.target, state.context, ttype, prior_terms,
                        state.aliases)
    # Adaptive layer: the model tailors angles to whoever the target is. The
    # heuristic sweep above is the deterministic floor (and its keyword-based
    # education hint is only a no-LLM fallback); this is the universal path.
    if agent is not None and getattr(agent, "enabled", False) and state.context:
        for q in _llm_angle_queries(state, agent, log):
            if q not in qs:
                qs.append(q)
    _log(log, f"recon sweep ({len(qs)}): " + " | ".join(qs))
    results = _run_queries(sources, qs, fetcher, state, seen, log)

    # Second pass: reach past the login walls via the index, routed only to
    # engines that understand operators.
    dork_sources = [s for s in sources if s.kind in _OPERATOR_KINDS]
    dorks = _wall_dorks(state.target, state.context, ttype, state.aliases)
    if dorks and dork_sources:
        _log(log, f"wall dorks ({len(dorks)}) via "
                  f"{', '.join(s.key for s in dork_sources)}: "
                  + " | ".join(d[:44] for d in dorks))
        unhonoured = 0
        for d in dorks:
            got = _run_queries(dork_sources, [d], fetcher, state, seen, log)
            if _dork_was_honoured(d, got):
                state.dork_results.extend(got)
                results = results + got
                unhonoured = 0
                continue
            # The engine answered, but not the question we asked. Those results
            # are the plain sweep again, so keeping them would inflate coverage
            # with duplicates and imply we searched a platform we never reached.
            unhonoured += 1
            if unhonoured >= _DORK_PATIENCE:
                state.dork_honoured = False
                skipped = len(dorks) - dorks.index(d) - 1
                state.notes.append(
                    f"login-walled platforms NOT reached: no configured engine "
                    f"honours search operators (a free SERP plan strips them; "
                    f"the RSS endpoint ignores them). {skipped} further dork "
                    f"quer(ies) skipped rather than spent on duplicates.")
                _log(log, f"wall dorks abandoned — operators not honoured; "
                          f"skipped {skipped} remaining")
                break
        else:
            state.dork_honoured = bool(state.dork_results)
        _log(log, f"wall dorks surfaced {len(state.dork_results)} "
                  f"additional result(s)")
    elif dorks:
        state.dork_honoured = False
        state.notes.append(
            "no operator-capable engine available — login-walled platforms "
            "(LinkedIn/Instagram/Facebook/…) were not reachable this run")

    # Reflection: read what came back and, if none of it names the person,
    # diagnose the miss and search again on the diagnosis rather than shipping
    # the failed sweep as the answer.
    recovered = reflect_and_retry(state, ttype, sources, fetcher, seen, agent,
                                  results, log)
    if recovered:
        results = results + recovered

    state.recon_results = results
    state.recon_ran = True

    # Say out loud how much of the haul is actually about the person. A sweep
    # dominated by the organisation looks productive and is not, and an
    # operator should not have to open the evidence list to discover that.
    person, ctx_only = org_vs_person(results, state)
    state.person_results, state.context_results = person, ctx_only
    _log(log, f"recon collected {len(results)} unique result(s) "
              f"— {person} about the person, {ctx_only} about the context only")
    if results and ctx_only > person * 2 and ctx_only >= 4:
        state.notes.append(
            f"result set is dominated by the CONTEXT, not the individual: "
            f"{ctx_only} page(s) about the organisation/qualifier vs {person} "
            f"naming the person. Pages about a school are not findings about "
            f"a pupil.")
    return results


# ---- phase 2: cluster into candidates --------------------------------------

_CLUSTER_SCHEMA = (
    '{"candidates":[{"label":"short distinguishing label","role":"",ّ'
    '"org":"","location":"","evidence":[0,1],"context_match":0.0,'
    '"why":"one line: why this scores as it does",'
    '"queries":["specific query that confirms THIS candidate"]}],'
    '"discarded":0}'
).replace("ّ", "")


def cluster_llm(state: DeepSearchState, results: list, agent, log=None,
                prior_summary: str = ""):
    """Ask the model to split the recon pile into distinct identities."""
    if not (agent and getattr(agent, "enabled", False)) or not results:
        return None
    ctx = state.context.strip()
    prompt = (
        f'TARGET NAME: "{state.target}"\n'
        + (f'USER-SUPPLIED CONTEXT: "{ctx}"\n' if ctx else "")
        + (f'PREVIOUSLY CONFIRMED IDENTITY (from an earlier run — prefer the '
           f'candidate matching this, but do NOT invent evidence for it): '
           f'"{prior_summary}"\n' if prior_summary else "")
        + f"\nRAW SEARCH RESULTS:\n{_corpus(results)}\n\n"
        "These results may describe SEVERAL DIFFERENT REAL PEOPLE who share "
        "this name, plus unrelated noise. Cluster them into DISTINCT candidate "
        "identities. Discard results that are not about a person with this "
        "name at all.\n"
        + (f"Score each candidate's context_match 0.0-1.0 on how well they fit "
           f"the user's context ({ctx}). A person with this name who is "
           f"unrelated to that context scores near 0.0 — do NOT inflate.\n"
           if ctx else
           "Score context_match 0.0-1.0 on how much corroborating evidence "
           "each candidate has.\n")
        + "For each candidate also give 3 SPECIFIC follow-up queries that would "
        "confirm THAT candidate and no other, using their role/org/location.\n"
        "QUERY RULES: no phrase quotes, no site:/OR/intitle: operators — "
        "free-tier search APIs reject them.\n"
        f"Respond ONLY with JSON: {_CLUSTER_SCHEMA}")
    datas = agent.fanout_json(
        "You are an OSINT identity-resolution agent. Output strict JSON only.",
        prompt, 2000, label="clustering")
    state.llm_calls += max(1, getattr(agent, "panel_n", 1))
    valid = [d for d in datas if isinstance(d.get("candidates"), list)]
    if not valid:
        return None
    n_models = len(valid)
    state.panel_models = max(state.panel_models, n_models)
    if n_models > 1:
        _log(log, f"clustering: {n_models} model(s) voted")
    data = {"candidates": _merge_cluster_votes(valid, results),
            "discarded": max((d.get("discarded") or 0) for d in valid)}

    cands = []
    for c in data["candidates"]:
        if not isinstance(c, dict) or not (c.get("label") or c.get("role")):
            continue
        ev = []
        for i in c.get("evidence") or []:
            if isinstance(i, int) and 0 <= i < len(results):
                r = results[i]
                # Same guard as the deep-dive judge: the model cites a result as
                # evidence for a candidate on topical/context overlap, so a page
                # about the school (naming a different pupil) can be attached to
                # this person. Keep only results that actually carry the name or
                # an alias — context alone corroborates, it does not identify.
                if is_about_target(f"{r.title} {r.snippet} {getattr(r, 'url', '')}",
                                   state.target, state.context, state.aliases):
                    ev.append(r)
        try:
            score = float(c.get("context_match") or 0.0)
        except (TypeError, ValueError):
            score = 0.0
        cand = Candidate(
            label=str(c.get("label") or "candidate")[:120],
            role=str(c.get("role") or "")[:120],
            org=str(c.get("org") or "")[:120],
            location=str(c.get("location") or "")[:80],
            context_match=max(0.0, min(1.0, score)),
            why=str(c.get("why") or "")[:200],
            evidence=ev)
        seeds = [sanitize_query(q) for q in (c.get("queries") or [])
                 if isinstance(q, str)]
        cand.attributes["seed_queries"] = [q for q in seeds if q][:4]
        # How much of the panel proposed this identity. Kept separate from
        # context_match, which means "matches the user's qualifier" — these
        # answer different questions and averaging them would hide both.
        votes = int(c.get("_votes") or 1)
        cand.attributes["panel_agreement"] = f"{votes}/{n_models}"
        if n_models > 1 and votes == 1:
            cand.attributes.setdefault("caveats", []).append(
                f"proposed by only 1 of {n_models} models")
        cands.append(cand)
    if not cands:
        # Distinguish "the model answered, and its answer is zero" from "the
        # model failed". An empty candidate list is a real verdict — every
        # result was a namesake — and reporting it as an unusable model output
        # is how a correct negative gets overwritten by weaker heuristics.
        if not data["candidates"]:
            state.notes.append(
                f"the model judged all {len(results)} recon result(s) to be "
                f"about someone else with this name")
            return []
        return None                     # entries present but none were usable
    state.notes.append(f"clustering discarded {data.get('discarded', '?')} "
                       f"result(s) as not-about-this-name")
    return cands


class _Union:
    """Tiny union-find, used to merge profile anchors into one identity."""

    def __init__(self):
        self.parent: dict = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _norm_label(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())


def _merge_cluster_votes(datas: list, results: list) -> list:
    """Fuse several models' clusterings of the SAME recon pile.

    Two models describe the same person in different words ("Wing Lam, analyst"
    vs "Kenneth Cho (Rotterdam)"), so labels cannot be the join key. Shared
    EVIDENCE can: if two proposed candidates cite any of the same result, they
    are about the same person. Groups formed that way carry how many models
    proposed them, which is the signal a single model cannot give you — a
    candidate every model saw is worth pursuing before one only a single model
    imagined.
    """
    groups: list[dict] = []
    for mi, d in enumerate(datas):
        for c in d.get("candidates") or []:
            if not isinstance(c, dict):
                continue
            ev = {i for i in (c.get("evidence") or [])
                  if isinstance(i, int) and 0 <= i < len(results)}
            lab = _norm_label(c.get("label"))
            hit = None
            for g in groups:
                if (ev and g["ev"] & ev) or (lab and lab in g["labels"]):
                    hit = g
                    break
            if hit is None:
                groups.append({"ev": set(ev), "labels": {lab} if lab else set(),
                               "entries": [c], "models": {mi}})
            else:
                hit["ev"] |= ev
                if lab:
                    hit["labels"].add(lab)
                hit["entries"].append(c)
                hit["models"].add(mi)

    def _pick(entries, key):
        vals = [str(e.get(key) or "").strip() for e in entries]
        vals = [v for v in vals if v]
        if not vals:
            return ""
        # the value the most models used, longest as the tiebreak
        return max(sorted(set(vals)), key=lambda v: (vals.count(v), len(v)))

    merged = []
    for g in groups:
        entries = g["entries"]
        scores = []
        for e in entries:
            try:
                scores.append(float(e.get("context_match") or 0.0))
            except (TypeError, ValueError):
                pass
        queries, seen_q = [], set()
        for e in entries:
            for q in e.get("queries") or []:
                if isinstance(q, str) and q.strip().lower() not in seen_q:
                    seen_q.add(q.strip().lower())
                    queries.append(q)
        merged.append({
            "label": _pick(entries, "label") or "candidate",
            "role": _pick(entries, "role"),
            "org": _pick(entries, "org"),
            "location": _pick(entries, "location"),
            "why": _pick(entries, "why"),
            "evidence": sorted(g["ev"]),
            "queries": queries,
            "context_match": (sum(scores) / len(scores)) if scores else 0.0,
            "_votes": len(g["models"]),
        })
    # most-agreed first, then best context match
    merged.sort(key=lambda m: (-m["_votes"], -m["context_match"]))
    return merged


# An operator's identification outranks every inferred verdict: it is the only
# outcome in this table sourced from a human rather than from evidence volume.
_OUTCOME_RANK = {"operator-confirmed": 6, "confirmed": 5, "weak": 3,
                 "budget": 2, "dry": 2, "awaiting-selection": 1,
                 "pending": 1, "skipped": 0, "excluded": -1}

# Outcomes that mean "we know who this is". Everything reading identity
# resolution must consult this set — checking for the bare string "confirmed"
# silently excluded operator picks and made resolution unreachable.
RESOLVED_OUTCOMES = frozenset({"confirmed", "operator-confirmed"})


def _better_outcome(a: str, b: str) -> str:
    return a if _OUTCOME_RANK.get(a, 1) >= _OUTCOME_RANK.get(b, 1) else b


def collapse_duplicate_candidates(cands: list, log=None) -> list:
    """Merge candidates that are obviously the SAME individual.

    Clustering a common name against a single-person query can emit two entries
    for one person — "Wong Jing Yi (Ko Lui Secondary School Student)" and
    "Wong Jing Yi (Hong Kong Student)" — which then makes the loop keep asking the
    operator "are these the same person?" forever. Collapse them when they share
    the same normalized (role, org, location) or one label contains the other,
    unioning evidence/attributes and keeping the strongest score and outcome.

    Operator-excluded candidates are never merged away — a `/refine`/`/focus`
    ruling stands.
    """
    out: list = []
    for c in cands:
        if getattr(c, "outcome", "") == "excluded":
            out.append(c)
            continue
        triple = tuple(_norm_label(x) for x in (c.role, c.org, c.location))
        target = None
        for o in out:
            if o.outcome == "excluded":
                continue
            o_triple = tuple(_norm_label(x) for x in (o.role, o.org, o.location))
            same_triple = any(triple) and triple == o_triple
            a, b = _norm_label(c.label), _norm_label(o.label)
            label_sub = bool(a) and bool(b) and (a in b or b in a)
            if same_triple or label_sub:
                target = o
                break
        if target is None:
            out.append(c)
            continue
        # fold c into target
        have = {_result_key(r) for r in target.evidence}
        for r in c.evidence:
            if _result_key(r) not in have:
                have.add(_result_key(r))
                target.evidence.append(r)
        target.context_match = max(target.context_match, c.context_match)
        target.rounds = max(getattr(target, "rounds", 0), getattr(c, "rounds", 0))
        target.outcome = _better_outcome(target.outcome, c.outcome)
        if len(c.label) > len(target.label):
            target.label = c.label
        for k, v in (c.attributes or {}).items():
            target.attributes.setdefault(k, v)
    if log and len(out) < len(cands):
        _log(log, f"merged {len(cands) - len(out)} duplicate candidate(s) "
                  f"(same individual)")
    return out


# Markers that a candidate is a *higher-tier / overseas* person — the kinds the
# operator's constraint typically excludes ("secondary student, NOT university /
# PhD / overseas"). Used only to DESCRIBE a candidate's constraint fit for the
# human; it never auto-decides who the target is.
# Person target types that get the Phase-5 human-selection gate by default.
_PERSON_TYPES = {"name", "person"}


def constraint_status(cand: Candidate, state: DeepSearchState) -> tuple:
    """Does this candidate satisfy the operator's hard constraint (the context)?

    Returns (verdict, reason) where verdict is one of:
      supports    — evidence names this individual AND fits the context
      unverified  — the context matched, but no evidence names this individual
      contradicts — looks like an excluded kind (university/PhD/overseas) and did
                    not meet the context; a namesake, not the target
      unknown     — no hard constraint was supplied, or nothing to judge on

    This only DESCRIBES fit for the human's decision — it never selects the
    target, and it never lets a namesake inherit the target's context tag.
    """
    ctx = (state.context or "").strip()
    if not ctx:
        return ("unknown", "no hard constraint supplied")
    named = any(
        is_about_target(f"{r.title} {r.snippet} {getattr(r, 'url', '')}",
                        state.target, "", state.aliases)
        for r in cand.evidence)
    meets_ctx = cand.context_match >= MIN_CONTEXT_MATCH
    # A concrete COMPETING identity: the candidate carries its own role / org /
    # location describing a specific, different person. Combined with a low
    # context match, THAT is the contradiction — no hardcoded list of which
    # professions "count" (the old code assumed the target was never in higher
    # education, which breaks the moment the target IS a professor or PhD). This
    # is symmetric and universal: a professor namesake contradicts a pupil
    # target, and a pupil namesake contradicts a professor target, by the same
    # rule — a mismatch is a mismatch, whoever the target is.
    _EMPTY = {"", "unknown", "various", "multiple", "n/a", "none", "-"}
    identity = [str(x).strip() for x in (cand.role, cand.org, cand.location)
                if str(x).strip().lower() not in _EMPTY]
    if named and meets_ctx:
        return ("supports",
                "evidence names this individual and fits the constraint")
    if meets_ctx and not named:
        return ("unverified",
                "matches the constraint context, but no evidence names this "
                "specific individual")
    if not meets_ctx and identity:
        return ("contradicts",
                f"a different person ({' / '.join(identity)[:60]}) — does not "
                f"fit the constraint '{ctx[:50]}'")
    return ("unknown", "insufficient evidence to judge the constraint")


def cluster_heuristic(state: DeepSearchState, results: list) -> list:
    """No-LLM fallback: treat distinct profile URLs as identity anchors.

    Weaker than model clustering (it cannot read a job title), but it still
    separates two people who own two different LinkedIn profiles — the
    distinction that matters most for a common name.

    Anchors that appear together in the SAME result are merged: a page listing
    both a LinkedIn profile and a GitHub account is evidence they belong to one
    person, which stops one individual being reported as several candidates.
    """
    on_target = [r for r in results
                 if is_about_target(f"{r.title} {r.snippet} {r.url}",
                                    state.target, state.context,
                                    state.aliases)]
    # 1st pass: link anchors that co-occur in a single result
    uf = _Union()
    for r in on_target:
        blob = f"{r.title} {r.snippet} {r.url}"
        found = {a.lower() for a in _profile_anchors(r)}
        for pat in _PROFILE_PATTERNS:          # anchors named in the text too
            found.update(m.lower() for m in pat.findall(blob))
        found = {a for a in found
                 if a not in ("in", "company", "posts", "search", "p", "pub")}
        anchors = sorted(found)
        for a in anchors[1:]:
            uf.union(anchors[0], a)

    buckets: dict = {}
    general: list = []
    for r in on_target:
        anchors = [a.lower() for a in _profile_anchors(r)]
        if anchors:
            buckets.setdefault(uf.find(anchors[0]), []).append(r)
        else:
            general.append(r)

    cands = []
    ctx_tokens = [t.lower() for t in re.findall(r"[A-Za-z0-9]+", state.context)
                  if len(t) > 2]
    for key, rs in buckets.items():
        blob = " ".join(f"{r.title} {r.snippet}" for r in rs).lower()
        hits = sum(1 for t in ctx_tokens if t in blob)
        score = min(1.0, (hits / len(ctx_tokens)) if ctx_tokens else 0.5)
        # every anchor merged into this identity, not just the representative
        merged = sorted({a.lower() for r in rs for a in _profile_anchors(r)
                         if uf.find(a.lower()) == key})
        cands.append(Candidate(
            label=f"{state.target} ({'/'.join(merged[:3]) or key})",
            context_match=score,
            why=(f"{len(merged)} linked profile anchor(s) across "
                 f"{len(rs)} corroborating result(s)"),
            attributes={"usernames": merged or [key]}, evidence=rs))
    if general:
        blob = " ".join(f"{r.title} {r.snippet}" for r in general).lower()
        hits = sum(1 for t in ctx_tokens if t in blob)
        cands.append(Candidate(
            label=f"{state.target} (unanchored results)",
            context_match=min(0.5, (hits / len(ctx_tokens)) * 0.5
                              if ctx_tokens else 0.25),
            why="on-target results with no distinct profile anchor",
            evidence=general))
    return cands


def cluster(state: DeepSearchState, results: list, agent, log=None,
            prior_summary: str = "") -> list:
    cands = cluster_llm(state, results, agent, log, prior_summary)
    if cands:
        state.mode = "llm"
    else:
        # `[]` is a verdict (every result was a namesake); `None` is a failure.
        # Both still get the heuristic pass as a safety net, but only one of
        # them is a fallback — and saying so is the difference between "we
        # could not run the model" and "the model looked and found nobody".
        model_answered = cands is not None
        cands = cluster_heuristic(state, results)
        state.mode = "heuristic"
        if results and model_answered:
            state.notes.append(
                "these candidates come from heuristic profile-anchor "
                "clustering, NOT the model — treat them as possible namesakes")
        elif results:
            state.notes.append(
                "candidate clustering used the heuristic profile-anchor "
                "fallback (no LLM available or model output unusable)")
    # one person can be clustered as several near-identical candidates; collapse
    # them so the loop stops asking the operator "are these the same person?"
    cands = collapse_duplicate_candidates(cands, log)
    cands.sort(key=lambda c: -c.context_match)
    panel = (f", {state.panel_models} model(s) voting"
             if state.panel_models > 1 else "")
    _log(log, f"clustered into {len(cands)} candidate(s) [{state.mode}{panel}]")
    for i, c in enumerate(cands, 1):
        agree = (c.attributes or {}).get("panel_agreement")
        _log(log, f"  [{i}] {c.label[:58]}  match={c.context_match:.2f}"
                  + (f"  agree={agree}" if agree and state.panel_models > 1 else "")
                  + (f"  {c.role[:40]}" if c.role else ""))
    return cands


# ---- phase 3: per-candidate deep dive --------------------------------------

# Broad facet pool for the autonomous dig. Once a candidate's own seed/anchor
# queries are spent, these give the loop genuinely NEW angles to try — the fix
# for a repeated /dig that used to no-op because the generator kept re-emitting
# the same (already-run) queries. Each facet is combined with every name form
# and the context, then filtered against what the candidate already searched.
_DIG_FACETS = (
    "profile", "interview", "award", "prize", "scholarship", "honour roll",
    "competition", "championship", "team", "club", "sports", "athletics",
    "music", "orchestra", "choir", "debate", "speech day", "prize day",
    "yearbook", "newsletter", "gallery", "results", "ranking", "news",
    "article", "linkedin", "instagram", "facebook", "youtube", "github",
    "biography", "volunteer", "project", "exhibition", "performance",
    "graduation", "alumni", "class photo", "student council",
)


def _round_queries_heuristic(state: DeepSearchState, cand: Candidate,
                             depth: int) -> list:
    """Fresh queries for this round, widening as the dig continues.

    Early on it uses the candidate's own seed/anchor terms for precision. Once
    those are exhausted — which is what made a repeated /dig a no-op — it draws
    from a broad facet pool crossed with every name form (romanisation, native
    script, aliases) and the context. Everything is filtered against the queries
    this candidate has already run, so each pass returns something genuinely new
    until the whole pool is spent (then it returns [], and the loop stops for a
    real reason instead of silently repeating itself).
    """
    run = {q.strip().lower() for q in cand.queries_run}

    def _fresh(cands: list) -> list:
        out: list = []
        taken = set(run)
        for q in cands:
            q = sanitize_query(q)
            key = q.strip().lower()
            if q and key not in taken:
                taken.add(key)
                out.append(q)
        return out

    seeds = cand.attributes.get("seed_queries") or []
    if depth == 1 and seeds:
        picked = _fresh(seeds)
        if picked:
            return picked[:QUERIES_PER_ROUND]

    anchors = cand.anchor_terms()
    base = state.target
    ctx = state.context.strip()
    names = [base] + [a for a in (state.aliases or []) if a]
    pool: list = []
    # 1. name x strongest discovered attributes (most specific first)
    for a in anchors:
        for nm in names:
            pool.append(f"{nm} {a}")
    # 2. alternative renderings of the primary name x context (surname-first /
    #    official romanisation are how records are often filed)
    for alt in _name_variants(base):
        pool.append(f"{alt} {ctx}".strip())
    # 3. every name form x facet x context — the broad widening that keeps the
    #    dig productive round after round
    for f in _DIG_FACETS:
        for nm in names:
            pool.append(f"{nm} {ctx} {f}".strip())

    return _fresh(pool)[:QUERIES_PER_ROUND]


def _merge_judgements(datas: list, n_fresh: int) -> dict:
    """Vote several models' verdicts on one candidate into a single answer.

    `belongs` is a MAJORITY vote: attributing a result to the wrong person is
    the expensive error in identity resolution — it is what puts a stranger's
    employer in someone's report — so a result is kept only when most of the
    panel agrees it belongs. `next_queries` and `new_attributes` are UNIONED
    instead: a lead only one model thought of still costs a single query to
    check, and missing it costs the whole finding. `saturated` needs unanimity,
    so one model giving up early cannot end the round for everyone.
    """
    n = len(datas)
    need = (n // 2) + 1 if n > 1 else 1
    tally: dict[int, int] = {}
    for d in datas:
        for i in set(x for x in (d.get("belongs") or [])
                     if isinstance(x, int) and 0 <= x < n_fresh):
            tally[i] = tally.get(i, 0) + 1
    belongs = sorted(i for i, c in tally.items() if c >= need)

    attrs: dict[str, list] = {}
    for d in datas:
        for k, vals in (d.get("new_attributes") or {}).items():
            if not isinstance(vals, list):
                continue
            bucket = attrs.setdefault(k, [])
            for v in vals:
                v = str(v).strip()
                if v and v.lower() not in {b.lower() for b in bucket}:
                    bucket.append(v)

    queries, seen = [], set()
    for d in datas:
        for q in (d.get("next_queries") or []):
            if isinstance(q, str) and q.strip() and q.strip().lower() not in seen:
                seen.add(q.strip().lower())
                queries.append(q)

    return {"belongs": belongs, "new_attributes": attrs,
            "next_queries": queries,
            "saturated": all(bool(d.get("saturated")) for d in datas),
            "votes": {"models": n, "needed": need,
                      "kept": len(belongs), "proposed": len(tally)}}


def _judge_and_extend(state: DeepSearchState, cand: Candidate, fresh: list,
                      agent, depth: int, log=None):
    """Judge new results against THIS candidate and harvest attributes.

    Returns (kept_results, next_queries, saturated). This is the reflection
    step: the model sees what came back, decides what actually belongs to the
    candidate, and chooses what to ask next — or says the candidate is done.
    """
    if not (agent and getattr(agent, "enabled", False)) or not fresh:
        kept = [r for r in fresh
                if is_about_target(f"{r.title} {r.snippet} {r.url}",
                                   state.target, state.context,
                                   state.aliases)]
        return kept, [], False

    known = {"label": cand.label, "role": cand.role, "org": cand.org,
             "location": cand.location, "attributes": cand.attributes}
    prompt = (
        f'TARGET NAME: "{state.target}"\n'
        + (f'CONTEXT: "{state.context}"\n' if state.context else "")
        + f"CANDIDATE UNDER INVESTIGATION (round {depth}):\n"
        f"{json.dumps(known, default=str)[:1200]}\n\n"
        f"NEW SEARCH RESULTS:\n{_corpus(fresh, 25)}\n\n"
        "Decide which of these results belong to THIS candidate (not to a "
        "different person with the same name, and not to unrelated pages). "
        "Extract any NEW attributes they reveal (employers, roles, locations, "
        "usernames/handles, affiliations, topics). Then propose the next "
        "queries that would reveal something you do NOT already know.\n"
        "Set saturated=true when further searching would only re-find what is "
        "already listed — do not pad with queries for their own sake.\n"
        "QUERY RULES: no quotes, no site:/OR operators.\n"
        'Respond ONLY with JSON: {"belongs":[0,2],'
        '"new_attributes":{"orgs":[],"roles":[],"locations":[],"handles":[],'
        '"usernames":[],"affiliations":[],"topics":[]},'
        '"next_queries":["..."],"saturated":false,'
        '"confidence":0.0}')
    datas = agent.fanout_json(
        "You are an OSINT analyst resolving one identity. Strict JSON only.",
        prompt, 1200, label="judging")
    state.llm_calls += max(1, getattr(agent, "panel_n", 1))
    if not datas:
        kept = [r for r in fresh
                if is_about_target(f"{r.title} {r.snippet} {r.url}",
                                   state.target, state.context,
                                   state.aliases)]
        return kept, [], False
    state.panel_models = max(state.panel_models, len(datas))
    data = _merge_judgements(datas, len(fresh))

    # The model decides what "belongs", but it over-attributes on CONTEXT: a
    # page that mentions the school (or city) but never the person gets voted in
    # — which is how a school award list naming a DIFFERENT pupil ended up cited
    # as evidence for the target. Gate every model-kept result through the same
    # deterministic name check `_grade` uses for the verdict: a result only
    # becomes this person's evidence if it actually carries the name or an alias
    # (with the context merely corroborating). Context-only pages are dropped
    # here rather than displayed as if they were about the individual.
    kept = []
    for i in data.get("belongs") or []:
        if isinstance(i, int) and 0 <= i < len(fresh):
            r = fresh[i]
            if is_about_target(f"{r.title} {r.snippet} {getattr(r, 'url', '')}",
                               state.target, state.context, state.aliases):
                kept.append(r)
            else:
                _log(log, f"    dropped context-only result (names the "
                          f"school/city, not the person): {r.title[:48]}")

    # Guard the "activity/interest" attributes against SNIPPET SPLICING. A
    # search engine builds a snippet by stitching non-adjacent page regions with
    # an ellipsis, so "Hong Kong Kin-ball Championships ... Lam Wing Kit, 4B" does
    # NOT mean this person does kin-ball — the name sits in a different fragment
    # (he was under an essay award). The name-gate proves the page names him; it
    # cannot prove an activity is his. So a snippet-prone attribute is kept only
    # when it shares an ellipsis-delimited fragment with the name.
    _names = [state.target.lower()] + [a.lower()
                                       for a in (state.aliases or []) if a]
    _texts = [f"{r.title} {r.snippet}".lower() for r in fresh] + [
        f"{getattr(r, 'title', '')} {getattr(r, 'snippet', '')}".lower()
        for r in cand.evidence]

    def _grounded(val: str) -> bool:
        vl = val.lower()
        for t in _texts:
            for frag in re.split(r"\.\.\.|…", t):
                if vl in frag and any(n in frag for n in _names):
                    return True
        return False

    _SNIPPET_ATTRS = {"affiliations", "topics"}
    dropped_terms: list = []   # ungrounded values, so we can also stop the
    #                            model re-querying them next round
    for key, vals in (data.get("new_attributes") or {}).items():
        if not isinstance(vals, list):
            continue
        bucket = cand.attributes.setdefault(key, [])
        for v in vals:
            v = str(v).strip()
            if not v or len(v) > 80 or v.lower() in {b.lower() for b in bucket}:
                continue
            if key in _SNIPPET_ATTRS and not _grounded(v):
                _log(log, f"    dropped ungrounded attribute {key}={v!r} "
                          f"(sits across a snippet ellipsis from the name — "
                          f"not verifiably his)")
                dropped_terms.append(v.lower())
                continue
            bucket.append(v)
        # keep the first-learned org/role/location on the candidate itself
        if key == "orgs" and not cand.org and bucket:
            cand.org = bucket[0]
        if key == "roles" and not cand.role and bucket:
            cand.role = bucket[0]
        if key == "locations" and not cand.location and bucket:
            cand.location = bucket[0]

    nxt = [sanitize_query(q) for q in (data.get("next_queries") or [])
           if isinstance(q, str)]
    nxt = [q for q in nxt if q]
    # Stop the model spending the next round chasing a term we just dropped as
    # ungrounded (e.g. it keeps proposing 'Kin-ball' queries after 'Kin-ball
    # Association' was rejected). Ban the distinctive token(s) of each dropped
    # value — skipping the person's own name tokens and generic place/qualifier
    # words, so genuine name+school queries are untouched.
    if dropped_terms:
        name_toks = set()
        for n in _names:
            name_toks.update(re.findall(r"[\w'-]+", n.lower()))
        # Only ban a dropped term's DISTINCTIVE token — a hyphenated compound
        # like 'kin-ball'. Common single words ('awards', 'sports') are left
        # searchable: they are exactly the generic terms that can still surface
        # the person's real page, so banning them would cost recall.
        ban = {tok for dt in dropped_terms
               for tok in re.findall(r"[\w'-]{4,}", dt.lower())
               if "-" in tok and tok not in name_toks}
        if ban:
            kept_q = [q for q in nxt if not any(b in q.lower() for b in ban)]
            if len(kept_q) < len(nxt):
                _log(log, f"    skipped {len(nxt) - len(kept_q)} next-quer(ies) "
                          f"built on dropped term(s): {', '.join(sorted(ban))}")
            nxt = kept_q
    return kept, nxt[:QUERIES_PER_ROUND], bool(data.get("saturated"))


def _grade(cand: Candidate, state: DeepSearchState, min_evidence: int) -> str:
    """Final verdict for a candidate.

    Evidence count alone is not enough: a candidate can accumulate pages that
    merely mention the name while matching the user's context not at all.
    Calling that "confirmed" is how a report ends up asserting an identity it
    scored 0.00. When a context was supplied, it gates the verdict.
    """
    if not cand.evidence:
        return "dry"
    # Count only evidence that NAMES the person. The judge assigns results to a
    # candidate on topical fit, so a school directory or a district listing —
    # pages that mention the org and never the individual — used to pad the
    # count toward `min_evidence`. Two such pages plus nothing else would grade
    # "confirmed" on zero evidence about the actual person. They stay attached
    # as context corroboration; they just no longer buy a verdict.
    named_evidence = [
        r for r in cand.evidence
        if is_about_target(f"{r.title} {r.snippet} {getattr(r, 'url', '')}",
                           state.target, "", state.aliases)]
    enough = len(named_evidence) >= min_evidence
    if state.context and cand.context_match < MIN_CONTEXT_MATCH:
        # corroborated as *someone*, but not as the person that was asked for
        return "weak"
    # The context matching the org/school is NOT the same as finding the person.
    # A candidate may pile up pages that name only the school (high context_match)
    # while not one of them names the individual — calling that "confirmed" is how
    # an empty-footprint person gets reported as found. Require that at least one
    # evidence item actually references the name/alias, checked with an EMPTY
    # context so only the person counts, never their school.
    if not named_evidence:
        return "weak"
    return "confirmed" if enough else "weak"


def deep_dive(state: DeepSearchState, cand: Candidate, sources: list, fetcher,
              seen: set, agent, log=None, *, budget: Optional[int] = None,
              max_depth: Optional[int] = None,
              dry_rounds: Optional[int] = None) -> None:
    """Iteratively investigate ONE candidate until it saturates or runs dry.

    The default budgets (MAX_DEPTH / QUERY_BUDGET / DRY_ROUNDS) are deliberately
    conservative — enough to profile a candidate without spraying the query
    quota. The optional overrides let a dedicated 'dig' run push much harder:
    more rounds, a bigger query budget, and a higher tolerance for empty rounds
    before it gives up, so the agent keeps self-directing new queries until the
    lead is genuinely exhausted.
    """
    bud = QUERY_BUDGET if budget is None else budget
    md = MAX_DEPTH if max_depth is None else max_depth
    dr = DRY_ROUNDS if dry_rounds is None else dry_rounds
    dry = 0
    pending: list = []
    # Rounds that stop returning anything NEW mean the search space is exhausted,
    # not that the candidate is empty. Stamping "dry" here used to skip _grade
    # entirely, discarding evidence already in hand — which is how a 0.95-match
    # candidate with corroborating evidence got reported as a miss. Only _grade
    # may pronounce a verdict; this flag just records how the loop ended.
    exhausted = False
    for depth in range(1, md + 1):
        if state.queries_spent >= bud:
            cand.outcome = cand.outcome if cand.outcome != "pending" else "budget"
            state.notes.append(f"'{cand.label[:40]}' stopped: query budget")
            break
        queries = pending or _round_queries_heuristic(state, cand, depth)
        pending = []
        queries = [q for q in queries if q not in cand.queries_run]
        if not queries:
            break
        cand.queries_run.extend(queries)
        _log(log, f"    round {depth}: " + " | ".join(q[:46] for q in queries))

        fresh = _run_queries(sources, queries, fetcher, state, seen, log)
        state.rounds_total += 1
        cand.rounds = depth
        if not fresh:
            dry += 1
            _log(log, f"    round {depth}: no new results ({dry}/{dr})")
            if dry >= dr:
                exhausted = True
                break
            continue

        kept, next_qs, saturated = _judge_and_extend(
            state, cand, fresh, agent, depth, log)
        before = len(cand.evidence)
        have = {_result_key(r) for r in cand.evidence}
        for r in kept:
            if _result_key(r) not in have:
                have.add(_result_key(r))
                cand.evidence.append(r)
        gained = len(cand.evidence) - before
        _log(log, f"    round {depth}: {len(fresh)} new result(s), "
                  f"{gained} belong to this candidate")

        if saturated:
            cand.outcome = _grade(cand, state, min_evidence=2)
            _log(log, f"    saturated at round {depth}")
            break
        if gained == 0:
            dry += 1
            if dry >= dr:
                exhausted = True
                break
        else:
            dry = 0
        pending = next_qs

    if cand.outcome == "pending":
        # Exhausting the query space IS saturation, discovered empirically
        # rather than declared by the judge, so it grades on the same evidence
        # bar (2) as the agent-declared `saturated` exit above. Only a run that
        # stopped early for another reason faces the stricter bar.
        cand.outcome = _grade(cand, state,
                              min_evidence=2 if exhausted else 3)


# ---- orchestration ---------------------------------------------------------

# An unexpanded acronym is the single strongest ambiguity signal in a
# qualifier: "SBC" is a bank, a school and a broadcaster, and picking one at
# random produces a confident answer about the wrong person.
_ACRONYM = re.compile(r"(?<![A-Za-z])[A-Z]{2,6}(?![A-Za-z])")

# "Who is the person in the photo?" is the operator's question, not ours.
# Asking it back is worse than saying nothing.
_ECHO_QUESTION = re.compile(
    r"\bwho\s+(?:is|are|was|were)\b|\bwhat\s+is\s+(?:the\s+)?(?:name|identity)\b"
    r"|\bidentify\s+(?:the|this)\b|\bcan\s+you\s+name\b", re.I)
_COMMON_ACRONYMS = {"AI", "IT", "HR", "PHD", "CEO", "CTO", "CFO", "USA", "UK",
                    "EU", "UN", "NGO", "LLC", "LTD", "INC", "ML", "LLM"}


def ambiguity_reasons(state: DeepSearchState, cands: list) -> list:
    """Why this search cannot resolve itself. Empty means it is confident."""
    reasons = []
    acronyms = [a for a in _ACRONYM.findall(state.context or "")
                if a.upper() not in _COMMON_ACRONYMS]
    for a in acronyms:
        reasons.append(f"'{a}' is an unexpanded abbreviation and could mean "
                       f"several different organisations")
    if not cands:
        reasons.append("no candidate could be separated out of the results")
        return reasons
    top = cands[0].context_match
    if top < 0.5:
        reasons.append(f"the best candidate only scores {top:.2f} against the "
                       f"context given")
    if len(cands) >= 2 and (top - cands[1].context_match) < 0.2:
        reasons.append(f"the top two candidates score within "
                       f"{top - cands[1].context_match:.2f} of each other and "
                       f"cannot be told apart from public data")
    return reasons


def clarifying_questions(state: DeepSearchState, cands: list, agent,
                         log=None) -> list:
    """Ask the operator what the web cannot tell us.

    Modelled on how a good analyst behaves: when a qualifier is ambiguous, one
    question ("is SBC a bank or a school?") is worth more than another twenty
    queries. Questions are returned, never invented answers.
    """
    reasons = ambiguity_reasons(state, cands)
    if not reasons:
        return []

    # Deterministic fallback so this works with no model at all.
    fallback = []
    for a in [x for x in _ACRONYM.findall(state.context or "")
              if x.upper() not in _COMMON_ACRONYMS]:
        fallback.append(f"What does '{a}' stand for — a company, a school, or "
                        f"something else?")
    if len(cands) >= 2:
        opts = " / ".join(c.label[:38] for c in cands[:3])
        fallback.append(f"Which of these is the one you mean? {opts}")
    if not fallback:
        fallback.append("What else do you know about them — employer, city, "
                        "role, or a platform they use?")

    if not (agent and getattr(agent, "enabled", False)):
        return fallback[:3]

    payload = [{"label": c.label, "role": c.role, "org": c.org,
                "location": c.location, "score": c.context_match}
               for c in cands[:5]]
    prompt = (
        f'TARGET: "{state.target}"\n'
        f'CONTEXT GIVEN: "{state.context}"\n'
        f"WHY THIS IS AMBIGUOUS:\n" + "\n".join(f"  - {r}" for r in reasons)
        + f"\n\nCANDIDATES FOUND:\n{json.dumps(payload)[:2500]}\n\n"
        "Write up to 3 SHORT questions for the operator that would most "
        "quickly resolve this. Rules:\n"
        "  * Ask only what a person who knows the target could answer and the "
        "open web cannot.\n"
        "  * NEVER ask the operator to identify the target ('who is this "
        "person?'). That is what they asked YOU. Ask instead for facts that "
        "would let a search find them: an employer, a school, a city, a "
        "username, a platform, an event they attended.\n"
        "  * If an abbreviation is ambiguous, ask what it stands for and offer "
        "the plausible readings as options.\n"
        "  * If several candidates are close, ask which one, naming them.\n"
        "  * Do not ask for anything sensitive or non-public beyond what is "
        "needed to tell two public profiles apart.\n"
        'JSON only: {"questions":["..."]}')
    out = agent._complete(
        "You are an OSINT analyst asking for the missing detail. JSON only.",
        prompt, 500)
    state.llm_calls += 1
    data = _json_from(out)
    qs = [str(q).strip() for q in ((data or {}).get("questions") or [])
          if str(q).strip()]
    # Drop any question that just hands the operator's own question back.
    qs = [q for q in qs if not _ECHO_QUESTION.search(q)]
    return (qs or fallback)[:3]


def _name_variants(target: str) -> list:
    """Plausible alternative renderings of a personal name.

    A person is often indexed under a form other than the one you were given —
    an official romanisation beside an everyday English name, or surname-first
    ordering. Searching only the given form misses those records entirely.
    """
    t = re.sub(r"\s+", " ", (target or "").strip())
    parts = [p for p in t.split(" ") if p]
    if len(parts) < 2 or len(t) > 60:
        return []
    out = []
    out.append(" ".join(reversed(parts)))                    # surname-first
    out.append(f"{parts[0][0]}. {' '.join(parts[1:])}")      # initialled given
    if len(parts) > 2:                                       # drop middle
        out.append(f"{parts[0]} {parts[-1]}")
    seen, uniq = {t.lower()}, []
    for v in out:
        if v.lower() not in seen and len(v) > 2:
            seen.add(v.lower())
            uniq.append(v)
    return uniq[:3]


def _candidate_from_dict(d: dict) -> Candidate:
    """Rebuild a Candidate from a serialised deep_search state."""
    c = Candidate(
        label=d.get("label", ""), role=d.get("role", ""), org=d.get("org", ""),
        location=d.get("location", ""), why=d.get("why", ""),
        context_match=float(d.get("context_match") or 0.0),
        attributes=dict(d.get("attributes") or {}),
        queries_run=list(d.get("queries_run") or []),
        rounds=int(d.get("rounds") or 0), outcome=d.get("outcome", "pending"))
    c.evidence = [SearchResult(
        source=r.get("source", "prior"), surface=r.get("surface", "public"),
        title=r.get("title", ""), url=r.get("url", ""),
        snippet=r.get("snippet", ""), is_onion=bool(r.get("is_onion")))
        for r in (d.get("evidence") or []) if isinstance(r, dict)]
    return c


def rescore_with_detail(state: DeepSearchState, cands: list, extra: str,
                        agent, log=None) -> list:
    """Re-judge existing candidates against a new detail from the user.

    The user knows things the web does not surface — an age, a school, a
    project, "not the one in Sydney". Applying that to candidates already found
    is far cheaper than searching again, and it is the step that turns three
    plausible people into one.
    """
    if not cands:
        return cands
    if not (agent and getattr(agent, "enabled", False)):
        # No model: keyword-boost candidates whose text matches the new detail.
        toks = [t.lower() for t in re.findall(r"[A-Za-z0-9]+", extra)
                if len(t) > 2]
        for c in cands:
            blob = " ".join([c.label, c.role, c.org, c.location] +
                            [f"{r.title} {r.snippet}" for r in c.evidence]).lower()
            hits = sum(1 for t in toks if t in blob)
            if toks:
                c.context_match = min(1.0, c.context_match + 0.15 * hits)
                c.why = (c.why + f" | +{hits} match(es) for new detail").strip()
        cands.sort(key=lambda c: -c.context_match)
        return cands

    payload = [{"i": i, "label": c.label, "role": c.role, "org": c.org,
                "location": c.location, "score": c.context_match,
                "evidence": [r.title[:90] for r in c.evidence[:6]]}
               for i, c in enumerate(cands)]
    prompt = (
        f'TARGET: "{state.target}"\n'
        + (f'ORIGINAL CONTEXT: "{state.context}"\n' if state.context else "")
        + f'NEW DETAIL FROM THE USER: "{extra}"\n\n'
        f"CANDIDATES ALREADY FOUND:\n{json.dumps(payload)[:6000]}\n\n"
        "The user has supplied a new detail. Re-score every candidate against "
        "it and decide which are now EXCLUDED.\n"
        "  * The new detail is authoritative — the user knows the target.\n"
        "  * A candidate contradicting it should be excluded, not merely "
        "down-scored.\n"
        "  * Do not invent evidence: if the detail cannot be checked against "
        "what is known about a candidate, keep its score and say so.\n"
        "Also propose queries that use the NEW detail to find things the "
        "earlier rounds missed. No quotes, no site:/OR operators.\n"
        'Respond ONLY with JSON: {"verdicts":[{"i":0,"score":0.0,'
        '"excluded":false,"why":"one line"}],"queries":["..."]}')
    out = agent._complete(
        "You are an OSINT analyst refining an identification. JSON only.",
        prompt, 1200)
    state.llm_calls += 1
    data = _json_from(out)
    if not data:
        return cands

    kept = []
    for v in (data.get("verdicts") or []):
        if not isinstance(v, dict):
            continue
        i = v.get("i")
        if not isinstance(i, int) or not (0 <= i < len(cands)):
            continue
        c = cands[i]
        try:
            c.context_match = max(0.0, min(1.0, float(v.get("score") or 0.0)))
        except (TypeError, ValueError):
            pass
        c.why = (v.get("why") or c.why)[:200]
        if v.get("excluded"):
            c.outcome = "excluded"
            state.notes.append(
                f"'{c.label[:40]}' excluded by new detail: {c.why[:80]}")
            _log(log, f"excluded by new detail: {c.label[:48]}")
        else:
            kept.append(c)
    if not kept:                       # never refine down to nothing
        kept = sorted(cands, key=lambda c: -c.context_match)[:1]
        state.notes.append("new detail excluded every candidate; kept the "
                           "best-scoring one for review")
    seeds = [sanitize_query(q) for q in (data.get("queries") or [])
             if isinstance(q, str)]
    if seeds and kept:
        kept[0].attributes["seed_queries"] = [q for q in seeds if q][:4]
    kept.sort(key=lambda c: -c.context_match)
    return kept


def refine(prev_state: dict, extra: str, target: str, context: str,
           ttype: str, surfaces: list, fetcher, agent, *,
           only: Optional[list] = None, log=None) -> tuple:
    """Continue a finished investigation with an extra detail from the user.

    Reuses the candidates already found instead of re-running recon, so a
    follow-up costs a fraction of the original search.
    """
    merged_ctx = " ".join(x for x in ((context or "").strip(),
                                      (extra or "").strip()) if x)
    # Alternate names carry over: /refine adds a detail, it does not replace
    # what the original instruction already established about the subject.
    state = DeepSearchState(
        target=target, context=merged_ctx,
        aliases=list((prev_state or {}).get("aliases") or []))
    state.mode = (prev_state or {}).get("mode", "heuristic")
    sources = _public_sources(surfaces, only)
    cands = [_candidate_from_dict(d)
             for d in ((prev_state or {}).get("candidates") or [])
             if d.get("outcome") != "excluded"]
    if not cands:
        state.notes.append("no previous candidates to refine — run a search first")
        return state, []
    if not sources:
        state.notes.append("no public source available to refine with")
        return state, _as_runs(state)

    _log(log, f"refining {len(cands)} candidate(s) with: {extra[:60]!r}")
    cands = rescore_with_detail(state, cands, extra, agent, log)
    # collapse any same-person duplicates so refinement converges instead of
    # re-asking "are these the same individual?" every round.
    cands = collapse_duplicate_candidates(cands, log)
    state.candidates = cands

    # Phase 5: refinement narrows the candidate list but must NOT auto-pursue for
    # person targets — re-present the updated list and let the operator commit
    # with /focus. Only an explicit /focus starts deep research.
    gate = ttype in _PERSON_TYPES
    if gate and state.candidates:
        _present_for_selection(state, log)
        return state, _as_runs(state)

    seen: set = {_result_key(r) for c in cands for r in c.evidence}
    pursued = _select_candidates(state, log)
    for c in state.candidates:
        if c not in pursued and c.outcome not in ("excluded",):
            c.outcome = "skipped"
    for i, cand in enumerate(pursued, 1):
        cand.outcome = "pending"       # re-open for another pass
        _log(log, f"  candidate {i}/{len(pursued)}: {cand.label[:52]} "
                  f"(match {cand.context_match:.2f})")
        deep_dive(state, cand, sources, fetcher, seen, agent, log)
        _log(log, f"    -> {cand.outcome}, {len(cand.evidence)} evidence")
    # still ambiguous after the extra detail? ask again, more specifically.
    state.questions = clarifying_questions(state, pursued, agent, log)
    for q in state.questions:
        _log(log, f"? {q}")
    return state, _as_runs(state)


def focus(prev_state: dict, index: int, target: str, context: str,
          ttype: str, surfaces: list, fetcher, agent, *,
          only: Optional[list] = None, log=None,
          budget: Optional[int] = None, max_depth: Optional[int] = None,
          dry_rounds: Optional[int] = None) -> tuple:
    """Pin the deep-dive to ONE operator-chosen candidate.

    Clustering a common name produces several same-name candidates. When the
    operator can say *which* one is the target, this pursues only that one and
    marks every other as an explicitly ruled-out namesake — so they are neither
    profiled nor re-queried. That is the privacy-preserving choice: it stops the
    tool spreading its dig across strangers who merely share the name.

    `index` is 1-based, matching how candidates are listed to the operator.
    """
    state = DeepSearchState(
        target=target, context=(context or "").strip(),
        aliases=list((prev_state or {}).get("aliases") or []))
    state.mode = (prev_state or {}).get("mode", "heuristic")
    cands = [_candidate_from_dict(d)
             for d in ((prev_state or {}).get("candidates") or [])]
    if not cands:
        state.notes.append("no candidates to focus — run a search first")
        return state, []
    if not (1 <= index <= len(cands)):
        state.candidates = cands
        state.notes.append(
            f"candidate #{index} is out of range (pick 1..{len(cands)})")
        return state, _as_runs(state)

    chosen = cands[index - 1]
    # Everyone the operator did NOT pick is a different person: rule them out
    # explicitly, so they are never profiled or queried again.
    for i, c in enumerate(cands, 1):
        if i != index:
            c.outcome = "excluded"
            c.why = f"ruled out by operator — not the target (focused on #{index})"
    # The operator's pick IS the target, so pursue it regardless of the score
    # the clustering guessed; a below-floor score should not veto a human's call.
    if chosen.context_match < MIN_CONTEXT_MATCH:
        chosen.context_match = MIN_CONTEXT_MATCH
        state.notes.append(
            f"candidate #{index} pinned by operator; match raised to the "
            f"{MIN_CONTEXT_MATCH} floor so it is pursued")
    chosen.outcome = "pending"
    state.candidates = cands

    sources = _public_sources(surfaces, only)
    if not sources:
        state.notes.append("no public source available to focus with")
        return state, _as_runs(state)

    _log(log, f"focusing on candidate #{index}: {chosen.label[:52]} "
              f"(match {chosen.context_match:.2f}); "
              f"{len(cands) - 1} other(s) ruled out as namesakes")
    seen: set = {_result_key(r) for c in cands for r in c.evidence}
    deep_dive(state, chosen, sources, fetcher, seen, agent, log,
              budget=budget, max_depth=max_depth, dry_rounds=dry_rounds)
    # A human pointing at a candidate and saying "that is the target" IS the
    # identity resolution — it is the strongest signal in the pipeline, and it
    # outranks whatever _grade inferred from evidence volume. Grading still
    # describes how much corroboration was gathered; it no longer gets to
    # overturn the operator on WHO this is.
    if chosen.evidence:
        chosen.outcome = "operator-confirmed"
        state.notes.append(
            f"identity resolved by operator: candidate #{index} is the target "
            f"({len(chosen.evidence)} evidence item(s) gathered)")
    _log(log, f"    -> {chosen.outcome}, {len(chosen.evidence)} evidence")
    state.questions = clarifying_questions(state, [chosen], agent, log)
    for q in state.questions:
        _log(log, f"? {q}")
    return state, _as_runs(state)


def _select_candidates(state: DeepSearchState, log=None) -> list:
    """Choose which candidates are worth the query budget.

    With a user-supplied context, namesakes below MIN_CONTEXT_MATCH are not the
    target and are left un-profiled — but the top candidate is always kept, so
    a weak-scoring run still produces a dossier rather than nothing.
    """
    ranked = sorted(state.candidates, key=lambda c: -c.context_match)
    if not ranked:
        return []
    if state.context:
        keep = [c for c in ranked if c.context_match >= MIN_CONTEXT_MATCH]
        if not keep:
            keep = ranked[:1]
            state.notes.append(
                f"no candidate reached the context-match floor "
                f"({MIN_CONTEXT_MATCH}); profiled the best-scoring one only")
        dropped = len(ranked) - len(keep)
        if dropped:
            state.notes.append(
                f"{dropped} candidate(s) below the context-match floor "
                f"({MIN_CONTEXT_MATCH}) left un-profiled as namesakes")
            _log(log, f"skipping {dropped} namesake candidate(s) below "
                      f"match floor {MIN_CONTEXT_MATCH}")
        ranked = keep
    pursued = ranked[:MAX_CANDIDATES]
    if len(ranked) > MAX_CANDIDATES:
        state.notes.append(
            f"{len(ranked) - MAX_CANDIDATES} qualifying candidate(s) not "
            f"investigated (MAX_CANDIDATES={MAX_CANDIDATES})")
    return pursued


def run_deep_search(target: str, context: str, ttype: str, surfaces: list,
                    fetcher, agent, *, only: Optional[list] = None,
                    prior: Optional[dict] = None, log=None,
                    aliases: Optional[list] = None,
                    select_gate: Optional[bool] = None) -> tuple:
    """Run the full loop. Returns (DeepSearchState, [SourceRun] for the report).

    `prior` is a remembered entry from a previous run (see memory.recall). It
    only seeds queries and informs clustering — it never counts as evidence, so
    a stale memory can cost a couple of queries but cannot fabricate findings.

    `select_gate` controls Phase-5 human-in-the-loop selection: when True the
    loop clusters candidates and STOPS, presenting them for the operator to pick
    (via /focus) before any deep-dive. Default (None) turns it on for person
    targets and off for infra targets (domain/ip/etc.).
    """
    state = DeepSearchState(
        target=target, context=(context or "").strip(),
        aliases=[a.strip() for a in (aliases or []) if a and a.strip()])
    sources = _public_sources(surfaces, only)
    if not sources:
        state.notes.append("no public source available for the deep loop")
        return state, []

    from .memory import prior_terms as _prior_terms, summarize as _summarize
    terms = _prior_terms(prior)
    prior_summary = _summarize(prior)
    if terms:
        state.notes.append(f"warm start from memory: {', '.join(terms[:4])}")
        _log(log, f"memory: recalled {prior_summary[:70]}")

    seen: set = set()
    results = recon(state, ttype, sources, fetcher, seen, log, terms, agent)
    if not results:
        state.notes.append(
            "recon returned nothing — every public source was refused or empty; "
            "this is NOT evidence the target has no footprint")
        return state, _as_runs(state)

    state.candidates = cluster(state, results, agent, log, prior_summary)

    # Phase 5 — human-in-the-loop candidate selection (default for person
    # targets). STOP here: present EVERY candidate with its hard-constraint fit
    # and let the operator pick before ANY deeper research. No candidate is
    # auto-pursued, and a namesake never inherits the target's context tag.
    gate = select_gate if select_gate is not None else (ttype in _PERSON_TYPES)
    if gate and state.candidates:
        _present_for_selection(state, log)
        return state, _as_runs(state)

    # Non-gated path (non-person targets, or gate explicitly disabled): the loop
    # picks and pursues the best candidates itself, then asks if still ambiguous.
    pursued = _select_candidates(state, log)
    for c in state.candidates:
        if c not in pursued:
            c.outcome = "skipped"

    for i, cand in enumerate(pursued, 1):
        _log(log, f"  candidate {i}/{len(pursued)}: {cand.label[:56]} "
                  f"(match {cand.context_match:.2f})")
        deep_dive(state, cand, sources, fetcher, seen, agent, log)
        _log(log, f"    -> {cand.outcome}, {len(cand.evidence)} evidence item(s), "
                  f"{cand.rounds} round(s)")

    # Ask rather than guess when the result is still ambiguous.
    state.questions = clarifying_questions(state, state.candidates, agent, log)
    for q in state.questions:
        _log(log, f"? {q}")

    return state, _as_runs(state)


def _present_for_selection(state: DeepSearchState, log=None) -> None:
    """Phase-5 stop: tag each candidate with constraint fit, log them all, and
    set a selection prompt. Does NOT pursue anything — the human picks next."""
    for i, c in enumerate(state.candidates, 1):
        verdict, why = constraint_status(c, state)
        c.attributes["constraint"] = verdict
        c.attributes["constraint_reason"] = why
        if c.outcome in ("pending", ""):
            c.outcome = "awaiting-selection"
    ranked = sorted(state.candidates, key=lambda c: -c.context_match)
    _log(log, f"awaiting your selection — {len(ranked)} candidate(s), none "
              f"pursued yet (Phase 5):")
    for i, c in enumerate(ranked, 1):
        v = (c.attributes or {}).get("constraint", "unknown")
        _log(log, f"  [{i}] {c.label[:52]}  match={c.context_match:.2f}  "
                  f"constraint={v.upper()}  ({c.role or '—'})")
    state.notes.append(
        "Phase 5: stopped before deep research; no candidate pursued. Pick one "
        "with /focus <n> to start focused research on ONLY that candidate.")
    labels = " / ".join(f"[{i}] {c.label[:40]} ({(c.attributes or {}).get('constraint','?')})"
                        for i, c in enumerate(ranked, 1))
    state.questions = [
        "Which candidate is the real target? Reply with /focus <n>. "
        "Candidates: " + labels]


def _as_runs(state: DeepSearchState) -> list:
    """Expose the loop's findings as SourceRuns so the existing report renders
    them without needing to understand candidates."""
    spend = (f"{state.queries_spent} quer(ies) spent, "
             f"{state.llm_calls} LLM call(s), mode={state.mode}"
             + (f", {state.panel_models}-model panel"
                if state.panel_models > 1 else ""))
    if state.recon_ran:
        recon_status = "ok" if state.recon_results else "empty"
        recon_detail = (
            f"{state.person_results} result(s) name the individual, "
            f"{state.context_results} match only the context (organisation/"
            f"qualifier). " + spend)
    else:
        # Focused/refined continuation: the sweep belongs to the earlier run.
        # Reporting this as "empty" is what made a working Serper row point at
        # an apparently empty pile — "we did not re-run" reading as "we found
        # nothing" is the same false-negative this file guards against.
        recon_status = "skipped"
        recon_detail = ("no recon sweep in this run — focused continuation of a "
                        "previous sweep; engine rows below cover this run. " + spend)
    runs = [SourceRun("deepsearch_recon", "Deep search — recon sweep", "public",
                      recon_status, detail=recon_detail,
                      results=state.recon_results)]
    if state.reflected:
        # Its own row: an operator should be able to see that the first sweep
        # missed, what the loop concluded, and that it went back out again.
        why = [n for n in state.notes if n.startswith("reflection:")]
        runs.append(SourceRun(
            "deepsearch_reflect", "Reflection — re-query after a missed sweep",
            "public", "ok",
            detail=("the opening sweep returned nothing naming the target, so "
                    "the loop diagnosed the miss and searched again. "
                    + (" ".join(why) if why else
                       "Reformulated from the domains the results themselves "
                       "revealed.")),
            queries=list(state.tried_queries)))
    if state.recon_ran and WALL_DORKS > 0 and state.dork_honoured is not None:
        # Three-way, and the distinction is the entire value of this row:
        #   ok      - we asked about LinkedIn/Instagram and got answers
        #   empty   - we asked and the index genuinely had nothing
        #   blocked - we could not ask at all, because no engine obeys operators
        # Collapsing the third into "empty" would report an unsearched platform
        # as a clean one, which is the exact false negative this tool exists to
        # avoid. It is reported as `blocked` because the obstacle is external.
        if state.dork_honoured is False:
            dork_status = "blocked"
            dork_detail = (
                "NOT SEARCHED. No configured engine honours search operators: "
                "a free-tier SERP plan strips `site:`/`filetype:` before "
                "searching, the RSS endpoint ignores them, and the HTML "
                "endpoint refuses operator queries. The login-walled platforms "
                "were therefore never queried — this says nothing about whether "
                "the target has accounts there. Fix: a SERP plan that permits "
                "operators.")
        elif state.dork_results:
            dork_status = "ok"
            dork_detail = (f"{len(state.dork_results)} result(s) from platforms "
                           f"that refuse a direct fetch — read from the search "
                           f"index, never fetched or logged into.")
        else:
            dork_status = "empty"
            dork_detail = ("Operators were honoured, but the index held nothing "
                           "for this target on those platforms. Not proof no "
                           "account exists — only that none is publicly indexed.")
        runs.append(SourceRun(
            "deepsearch_walldorks",
            "Login-walled platforms (via search index)", "public",
            dork_status, detail=dork_detail,
            results=list(state.dork_results)))
    # One row per engine the loop used. The recon pile above is anonymous, so
    # without this the report never names which public engines actually ran —
    # a refused engine leaves no trace, and a working one gets no credit.
    # Results stay pooled in the recon row rather than being duplicated here;
    # these rows document participation.
    for key, h in sorted(state.source_health.items()):
        n_ok, n_q = h.get("ok", 0), h.get("queries", 0)
        if n_ok:
            detail = (f"answered {n_ok}/{n_q} recon quer(ies); results are "
                      f"pooled in the recon sweep above")
        else:
            detail = (f"contributed 0 result(s) across {n_q} recon quer(ies)"
                      + (f": {h['detail'][:80]}" if h.get("detail") else ""))
        runs.append(SourceRun(
            f"deepsearch_{key}", f"{h['label']} — recon", "public",
            "ok" if n_ok else (h.get("status") or "empty"), detail=detail))
    for i, c in enumerate(state.candidates, 1):
        label = f"Candidate {i}: {c.label}"[:80]
        detail = (f"match={c.context_match:.2f} · {c.outcome} · "
                  f"{c.rounds} round(s)"
                  + (f" · {c.role}" if c.role else "")
                  + (f" @ {c.org}" if c.org else "")
                  + (f" · {c.why}" if c.why else ""))
        # A ruled-out candidate is a stranger who shares the name. Keep the row
        # (the report should show WHO was excluded and why) but drop their
        # evidence: re-listing a namesake's profile URLs is exactly the
        # collateral exposure that asking the operator was meant to prevent.
        ruled_out = c.outcome in ("skipped", "excluded")
        evidence = [] if ruled_out else list(c.evidence)
        if ruled_out and c.evidence:
            detail += (f" · {len(c.evidence)} evidence item(s) withheld "
                       f"(ruled-out namesake — not profiled)")
        runs.append(SourceRun(
            f"deepsearch_candidate_{i}", label, "public",
            "skipped" if ruled_out else ("ok" if c.evidence else "empty"),
            detail=detail, results=evidence, queries=list(c.queries_run)))
    return runs
