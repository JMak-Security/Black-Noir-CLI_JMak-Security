"""The investigation pipeline: plan -> collect -> correlate -> synthesize -> report."""

from __future__ import annotations

import os
import re
from datetime import datetime

from .agent import Agent
from .config import MAX_QUERIES, MAX_RESULTS_MERGED, REGISTRY
from .connectors import run_source
from .models import SourceRun
from .entities import (classify_target, correlate, is_about_target,
                       resolve_target_type)
from .guardrails import Guardrails
from .http import Fetcher
from .inputs import process_input_dir, summarize_input
from .models import Investigation
from .preflight import run_preflight
from .report import render


class Console:
    """Tiny status printer (colour if the terminal supports it)."""
    def __init__(self, quiet: bool = False) -> None:
        self.quiet = quiet

    def line(self, msg: str) -> None:
        if not self.quiet:
            print(msg, flush=True)

    def step(self, msg: str) -> None:
        self.line(f"  \033[90m›\033[0m {msg}")

    def head(self, msg: str) -> None:
        self.line(f"\033[91m▮\033[0m \033[1m{msg}\033[0m")

    def section(self, title: str) -> None:
        """A phase divider so the flat status stream reads as grouped stages."""
        self.line(f"\n\033[96m┄┄\033[0m \033[1;96m{title}\033[0m")


# Placeholder subjects a model produces when an image carries no name. These
# describe a picture instead of naming anyone, and searching them literally
# ("person in photo.jpg combolist") spends the whole budget on pages about nobody.
_PERSON_WORDS = (r"person|people|man|men|woman|women|boy|girl|kid|kids|child|"
                 r"children|guy|dude|lad|teen|teenager|youth|male|female|"
                 r"individual|subject|face|someone|somebody|human|figure|"
                 r"student|adult|baby|toddler")
_IMAGE_WORDS = r"selfie|photo|photograph|image|picture|portrait|self-portrait|pic|snapshot"
# adjectives a model puts in front of a generic noun ("a young man in ...")
_ADJECTIVES = (r"young|older?|little|small|tall|short|smiling|unknown|"
               r"asian|black|white|male|female|middle-aged|teenage|adult")

_PLACEHOLDER_SUBJECT = re.compile(
    # "unknown / unidentified / anonymous ..."
    r"^\s*(?:an?\s+|the\s+)?(?:unknown|unidentified|unnamed|anonymous|"
    r"unrecognised|unrecognized)\b"
    # leads with a generic person or image noun, with or without a describing
    # adjective: "boy in ...", "the person", "a young man in the portrait"
    rf"|^\s*(?:an?\s+|the\s+)?(?:(?:{_ADJECTIVES})\s+)*"
    rf"(?:(?:{_PERSON_WORDS})|(?:{_IMAGE_WORDS}))\b"
    # mentions a file at all: "person in photo.jpg", "photo.jpg"
    r"|\.(?:jpe?g|png|webp|gif|bmp|tiff?|heic|heif|avif)\b",
    re.I)


def _is_placeholder_subject(subject: str) -> bool:
    """True when the 'subject' describes an image rather than identifying anyone.

    A filename is never an identifier, and neither is a noun phrase for a human
    being. Both mean the same thing: the image gave us no one to search for.
    """
    s = (subject or "").strip()
    return not s or bool(_PLACEHOLDER_SUBJECT.search(s))


def _darkweb_queries(subject: str, depth: str, context: str = "") -> list[str]:
    """Terse, leak-oriented keyword queries that dark-web indexes match well."""
    base = subject.strip().strip('"')
    qs = [base, f"{base} leak", f"{base} breach", f"{base} database",
          f"{base} dump"]
    # One context-qualified probe: onion indexes match short keywords, so the
    # qualifier is added as a single extra variation rather than to every query.
    if context:
        qs.insert(1, f"{base} {context}".strip())
    if depth == "deep":
        qs += [f"{base} leaked", f"{base} credentials", f"{base} combolist"]
    # dedupe, keep order
    return list(dict.fromkeys(q for q in qs if q))


# A source is abandoned only after this many CONSECUTIVE transport failures.
# One bad query must never retire a working source (a single quoted query used
# to 400 Serper and end its run, discarding every remaining variation).
_MAX_CONSECUTIVE_FAILS = 3


def _filter_offtarget(run: SourceRun, target: str, context: str,
                      aliases: list[str] | None = None) -> SourceRun:
    """Drop results that do not mention the target at all.

    Onion indexes and Telegram search match loose keywords and happily return
    drug listings, channel ads and engine boilerplate for a person's name.
    Presenting those under the target's heading is what makes a report look
    like it "found" a connection to a Telegram channel. They are dropped, and
    the count is reported so the omission is visible rather than silent.
    """
    if not run.results:
        return run
    kept, dropped = [], 0
    for r in run.results:
        blob = f"{r.title} {r.snippet} {r.url}"
        if is_about_target(blob, target, context, aliases):
            kept.append(r)
        else:
            dropped += 1
    if dropped:
        run.results = kept
        note = (f"{dropped} result(s) hidden: matched the engine's keyword "
                f"index but never mention '{target}'.")
        run.detail = (run.detail + " " + note).strip() if run.detail else note
        if not kept and run.status == "ok":
            run.status = "empty"
    return run


def _collect_source(src, queries: list[str], target: str, fetcher,
                    context: str = "",
                    aliases: list[str] | None = None) -> SourceRun:
    """Run one source across the full AI query set and merge deduped results.

    Breach APIs take the exact target only. For every other source we sweep
    every query variation. A `skipped`/`planned` status is configuration, not
    luck, so it stops the sweep immediately; `blocked`/`error` is per-query bad
    luck and only stops the sweep after several in a row.
    """
    # Breach APIs, IntelX (credit-metered), crt.sh/Wayback (domain lookups) and
    # external tools (Telepathy etc.) take the exact target once — they're
    # lookups, not keyword search engines that benefit from query variations.
    from .connectors import external_cmd_for
    single = (src.kind in ("breach", "intelx", "github", "rdap", "reverseip",
                           "hostsearch", "pdns", "wikidata")
              or bool(external_cmd_for(src.key)))
    run_queries = [target] if single else queries
    merged = SourceRun(src.key, src.label, src.surface, "empty")
    seen: set[str] = set()

    fails = 0
    for q in run_queries:
        r = run_source(src, q, fetcher)
        merged.queries.append(q)
        for res in r.results:
            k = (res.url or res.title).lower()
            if k and k not in seen:
                seen.add(k)
                merged.results.append(res)
        # promote status: ok > empty; keep the first informative detail
        if r.status == "ok":
            merged.status = "ok"
            merged.detail = merged.detail or r.detail
        elif merged.status != "ok":
            merged.status = r.status
            merged.detail = r.detail
        # missing key / no query API: every remaining variation fails the same
        # way, so stop now.
        if r.status in ("skipped", "planned"):
            break
        # transient refusal: try the other variations before giving up, since a
        # differently-phrased query often succeeds where one was rejected.
        if r.status in ("blocked", "error"):
            fails += 1
            if fails >= _MAX_CONSECUTIVE_FAILS:
                merged.detail = (merged.detail or "") + \
                    f" [abandoned after {fails} consecutive failures]"
                break
        else:
            fails = 0

    if merged.results:
        merged.status = "ok"
    merged.results = merged.results[:MAX_RESULTS_MERGED]
    # Keyword indexes (onion aggregators, Telegram search) need an on-target
    # check; breach APIs are keyed on the target by construction and are exempt.
    if src.kind in ("aggregator", "messenger"):
        merged = _filter_offtarget(merged, target, context, aliases)
    return merged


def investigate(target: str, surfaces: list[str], input_dir: str,
                output_dir: str, *, live: bool, use_llm: bool,
                only: list[str] | None, console: Console,
                provider: str | None = None,
                model: str | None = None,
                preflight: str = "warn",
                assume_yes: bool = False,
                reverse_image: str = "auto",
                all_sources: bool = False,
                make_pdf: bool = True,
                make_runbook: bool = True,
                enrich: str = "auto",
                deep_loop: str = "auto",
                memory_flag: str = "auto",
                multi_agent: bool = True,
                panel_size: str | None = None,
                active_persona: str | None = None,
                max_mode: bool = False) -> Investigation:
    guard = Guardrails()

    # Defensive preflight runs only when a live search is requested — a
    # plan-only run performs no network I/O, so isolation is moot.
    if live and preflight != "off":
        ok = run_preflight(preflight, assume_yes,
                           log=lambda m: console.step(m),
                           head=lambda m: console.head(m))
        if not ok:  # enforce with unmet requirements -> no network
            live = False
        console.line("")

    # Identity-egress isolation gate. Sources marked requires_isolation run
    # under an authenticated session on this host (Telepathy = a real Telegram
    # account) — they must never egress from the operator's real IP. By default
    # Black Noir brings up Docker + a VPN; if EITHER is still down these sources
    # are dropped for this run (the rest of the sweep proceeds untouched). Only
    # bothered when such a source is actually configured/available, so a dormant
    # Telepathy never triggers a VPN/Docker dance.
    iso_ok = True
    if live and any(s.requires_isolation and s.available
                    for s in REGISTRY.values()):
        from .preflight import ensure_isolation
        d_ok, v_ok = ensure_isolation(lambda m: console.step(m), assume_yes)
        iso_ok = d_ok and v_ok
        if not iso_ok:
            d_txt = "up" if d_ok else "\033[91mOFF\033[0m"
            v_txt = "up" if v_ok else "\033[91mOFF\033[0m"
            console.step(
                f"\033[93m⚠\033[0m isolation not ready — Docker {d_txt}, "
                f"VPN {v_txt}: identity-egress sources (e.g. Telepathy) "
                "disabled this run.")
        console.line("")

    # Opsec guard: warn if a live run might leak the real identity/IP.
    if live:
        from .persona import opsec_check, PersonaVault
        for w in opsec_check(active_persona, live, surfaces, PersonaVault()):
            console.step(f"\033[93m⚠ opsec:\033[0m {w}")

    fetcher = Fetcher(guard, live=live)
    agent = Agent(provider=provider, model=model, use_llm=use_llm,
                  log=lambda m: console.step(f"[llm] {m}"), panel=multi_agent,
                  panel_size_override=panel_size)

    console.head("Black Noir — new investigation")
    console.step(f"agent: {agent.label} · network: "
                 f"{'LIVE' if live else 'plan-only'} · surfaces: {', '.join(surfaces)}")
    if max_mode:
        console.step("\033[95m◆ MAX mode\033[0m — all surfaces · every source · "
                     "deep multi-round loop · max query budget "
                     "(expect higher API usage)")

    # 1. input folder (visual + logical) — done first so the target parser and
    #    reverse-image router can see what the images actually are.
    console.section("1 · Input & target")
    console.step("processing input/ folder …")
    input_context = process_input_dir(input_dir, vision=agent.vision)
    input_summary = summarize_input(input_context)
    has_images = bool(input_context.get("images"))
    if input_context.get("files"):
        st = ", ".join(sorted({i.get("subject_type", "?")
                               for i in input_context.get("images", [])})) or "-"
        console.step(f"input: {len(input_context['files'])} file(s), "
                     f"{len(input_context.get('images', []))} image(s) [{st}]")

    # 2. parse the free-form instruction into a concrete subject + intent
    parsed = agent.parse_target(target, has_images, input_summary)
    subject = (parsed.get("subject") or target).strip()
    depth = parsed.get("depth", "normal")
    # MAX mode overrides whatever depth the instruction implied: the whole point
    # is to spend the full budget on this one target regardless of phrasing.
    if max_mode:
        depth = "deep"
    ttype = resolve_target_type(parsed.get("subject_type"), subject)
    context = (parsed.get("context") or "").strip()
    aliases = [a.strip() for a in (parsed.get("aliases") or []) if a and a.strip()]

    # An image with no name in the instruction parses to a placeholder subject.
    # Searching that placeholder literally ("unknown subject image this") burns
    # the whole query budget on a string that identifies nothing. Pivot to the
    # strongest mark the vision pass actually read out of the image instead.
    image_pivot = ""
    if _is_placeholder_subject(subject):
        marks: dict[str, list[str]] = {}
        for img in input_context.get("images", []):
            for field, vals in (img.get("extracted") or {}).items():
                marks.setdefault(field, []).extend(v for v in vals if v)
        for field in ("handles", "usernames", "domains", "emails", "names",
                      "watermarks"):
            if marks.get(field):
                image_pivot = marks[field][0].strip().lstrip("@")
                break
        if image_pivot:
            console.step(f"image pivot: no name given — searching the strongest "
                         f"mark read from the image: {image_pivot!r}")
            subject = image_pivot
            ttype = classify_target(subject)
            context = ""          # the mark is the identity; 'this' is not context
        else:
            # The qualifier here is the vision model's own description of the
            # picture ("self-portrait indoors modern office"). Appending that
            # to queries searches the description, not the person.
            context = ""
            console.step("image: no usable marks extracted — no searchable "
                         "identifier. Skipping web search (a face is not a query).")
    inv = Investigation(
        target=subject, target_type=ttype, surfaces=surfaces,
        started=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        raw=target, context=context, aliases=aliases, intent=parsed,
        persona=active_persona or "",
    )
    inv.input_context = input_context
    console.step(f"subject: '{subject}'  ({ttype}, depth={depth})")
    if context:
        console.step(f"  context: '{context}' (applied to queries)")
    if aliases:
        console.step(f"  aliases: {', '.join(repr(a) for a in aliases)} "
                     f"(searched as well)")
    if subject.lower() != target.strip().lower():
        console.step(f"  parsed from instruction: {target!r}")

    # A subject that names nobody cannot be planned for. Printing a source list
    # and a query set that will never run reads as though a search happened.
    unsearchable = _is_placeholder_subject(subject)
    if unsearchable:
        inv.plan = {"engine": agent.label, "depth": depth, "selected": [],
                    "queries": [], "mode": "skipped",
                    "reasoning": "no searchable identifier",
                    "skipped_reason": (
                        "The input gave no identifier to search: the image "
                        "carries no readable mark (handle, watermark, domain, "
                        "name) and Black Noir does not identify people from "
                        "facial appearance.")}
        console.line("")
        console.head("Nothing to search")
        console.step("the image yielded no name, handle, watermark or domain, "
                     "and a face is not a query.")
        console.step("what would make this searchable:")
        console.step("  · a name, username or handle to start from")
        console.step("  · legible text in the image (badge, signage, screen)")
        console.step("  · where/when it was taken, or who they work or study with")
        console.step("or run the prepared reverse-image links below by hand, "
                     "with authorization.")
        console.line("")
        selected, queries, dark_queries = [], [], []
    else:
        # 3. plan
        console.section("2 · Plan")
        console.step("planning source selection …")
        inv.plan = agent.plan(inv, surfaces, input_summary, depth)
        inv.plan["engine"] = agent.label
        inv.plan["depth"] = depth
        selected = [s["key"] for s in inv.plan.get("selected", [])]
        if only:
            selected = ([k for k in selected if k in only]
                        or [k for k in only if k in REGISTRY])
        elif all_sources or depth == "deep":
            # A deep (or forced) sweep enlists EVERY applicable source for the
            # chosen surfaces — so the full dark-web toolset is actually used,
            # not just what the planner trimmed to.
            sel = set(selected)
            for s in REGISTRY.values():
                if s.surface in surfaces and s.available and s.key not in sel:
                    selected.append(s.key)
                    sel.add(s.key)
        raw_q = inv.plan.get("queries") or [subject]
        local_max_q = 10 if depth == "deep" else MAX_QUERIES
        # Queries keep whatever syntax the planner chose: the Serper connector
        # downgrades to plain keywords only if the API actually refuses
        # operators, so precision is preserved on plans that allow them.
        cleaned = [q.strip() for q in raw_q if q and q.strip()]
        # Guarantee the disambiguating context reaches the engines even if the
        # planner ignored it.
        if context and not any(context.lower() in q.lower() for q in cleaned):
            cleaned.insert(0, f"{subject} {context}")
        # Alternate names go in front of the generic "<subject> LinkedIn"-style
        # variations: a native-script or legal name is usually the single most
        # discriminating query available, and the budget is spent top-down.
        for alt in reversed(aliases):
            if not any(alt.lower() in q.lower() for q in cleaned):
                cleaned.insert(0, f"{alt} {context}".strip())
        queries = [q for q in dict.fromkeys(q.strip() for q in cleaned
                                            if q)][:local_max_q]
        if not queries:
            queries = [f"{subject} {context}".strip()]
        inv.plan["queries"] = queries
        console.step(f"planner picked {len(selected)} source(s): "
                     f"{', '.join(selected)}")
        console.step(f"query set ({len(queries)}): " + " | ".join(queries))

        # Dark-web indexes want SHORT, leak-oriented keywords — the long
        # natural-language queries that help public engines return noise there.
        dark_queries = _darkweb_queries(subject, depth, context)[:local_max_q]
        console.step(f"dark-web query set ({len(dark_queries)}): "
                     + " | ".join(dark_queries))

    # 4. collect
    # For a person/name target the public surface is searched by the iterative
    # candidate loop instead of a single fixed fan-out: a common name is
    # several different people, and one undifferentiated sweep cannot tell them
    # apart or notice that it searched badly. Other target types (domain,
    # email, username) are unambiguous enough for the one-shot path.
    # A placeholder subject is not searchable: with no mark to pivot to there is
    # nothing to query, and running the loop on the placeholder string produces
    # confident-looking findings about nobody.
    console.section("3 · Search")
    use_loop = (not unsearchable
                and (deep_loop == "on"
                     or (deep_loop == "auto" and ttype in ("name", "person"))))
    loop_state = None
    if use_loop and "public" in surfaces:
        from .deepsearch import run_deep_search
        from . import memory as _mem
        prior = _mem.recall(subject, context, flag=memory_flag)
        if prior:
            console.step(f"memory: prior run {prior.get('last_seen','')} — "
                         f"{_mem.summarize(prior)[:60]} "
                         f"(erase with --forget \"{subject}\")")
        console.step("deep loop: recon → cluster → prioritise → deep dive …")
        loop_state, loop_runs = run_deep_search(
            subject, context, ttype, surfaces, fetcher, agent,
            only=only, prior=prior, aliases=aliases,
            log=lambda m: console.step(f"  {m}"))
        inv.runs.extend(loop_runs)
        inv.deep_search = loop_state.to_dict()
        # Name every public engine the loop actually used, and why any of them
        # returned nothing. The loop merges all engines into one anonymous
        # result pile, so a refused engine would otherwise be invisible — and
        # "no results" would read as "no footprint" rather than "engine down".
        for key, h in sorted(loop_state.source_health.items()):
            tag = ("\033[92m✓\033[0m" if h.get("ok")
                   else {"blocked": "\033[93m⚠\033[0m",
                         "error": "\033[91m✗\033[0m"}.get(h.get("status"),
                                                          "\033[90m∅\033[0m"))
            note = f" — {h['detail'][:52]}" if h.get("detail") else ""
            console.step(f"  {tag} {h['label']:<24} "
                         f"{h.get('ok', 0)}/{h.get('queries', 0)} quer(ies) ok"
                         f"{note}")
        pursued = [c for c in loop_state.candidates if c.outcome != "skipped"]
        console.step(f"deep loop: {len(loop_state.candidates)} candidate(s), "
                     f"{loop_state.rounds_total} round(s), "
                     f"{loop_state.queries_spent} quer(ies), "
                     f"{loop_state.llm_calls} LLM call(s)")
        for c in pursued:
            console.step(f"  · {c.label[:52]} → {c.outcome} "
                         f"({len(c.evidence)} evidence)")
        if _mem.remember(subject, context, inv.deep_search, flag=memory_flag):
            console.step(f"memory: saved (erase: --forget \"{subject}\" "
                         f"· disable: --memory off)")
        # Asking beats guessing: surface what the operator could answer that
        # the open web cannot.
        if loop_state.questions:
            console.line("")
            console.head("To narrow this further, I need to ask")
            for q in loop_state.questions:
                console.step(f"\033[93m?\033[0m {q}")
            console.step("answer in chat with:  /refine <your answer>")
        # the loop owns the public *web* surface (engine/serp); the fixed sweep
        # covers dark-web plus every other public lookup (crt.sh, Wayback,
        # GitHub) that is target-keyed, not a keyword engine the NL loop suits.
        selected = [k for k in selected
                    if (REGISTRY.get(k) and (REGISTRY[k].surface != "public"
                        or REGISTRY[k].kind not in ("engine", "serp")))]

    # Drop sources that cannot physically run (no key, or no local command for
    # a source with no clearnet API), and identity-egress sources when the
    # VPN+Docker isolation gate is not satisfied. Reporting a dropped source as
    # "queried" overstates coverage: a source that never ran is not evidence of
    # anything.
    def _drop_reason(k: str) -> str | None:
        src = REGISTRY.get(k)
        if not src:
            return None
        if not src.available:
            return src.unavailable_reason
        if src.requires_isolation and not iso_ok:
            return "VPN+Docker required (one or both off) — identity-egress guard"
        return None

    unavailable = [(k, r) for k in selected
                   if (r := _drop_reason(k)) is not None]
    if unavailable:
        dropped = {k for k, _ in unavailable}
        selected = [k for k in selected if k not in dropped]
        for k, why in unavailable:
            console.step(f"\033[90m—\033[0m {REGISTRY[k].label:<20} not queried "
                         f"({why})")
            # Record the gap as a run so it reaches the REPORT, not just the
            # console. A source missing from the table is indistinguishable
            # from one that ran and found nothing — which is how a coverage
            # gap gets read as an absence of findings.
            inv.runs.append(SourceRun(k, REGISTRY[k].label, REGISTRY[k].surface,
                                      "skipped", detail=f"not queried: {why}"))
        inv.plan["unavailable"] = [{"key": k, "reason": w}
                                   for k, w in unavailable]

    # public engines get rich queries, dark-web gets terse ones
    for key in selected:
        src = REGISTRY.get(key)
        if not src or src.surface not in surfaces:
            continue
        qset = dark_queries if src.surface == "darkweb" else queries
        run = _collect_source(src, qset, subject, fetcher, context, aliases)
        inv.runs.append(run)
        tag = {"ok": "\033[92m✓\033[0m", "planned": "\033[95m◐\033[0m",
               "empty": "\033[90m∅\033[0m", "skipped": "\033[90m—\033[0m",
               "error": "\033[91m✗\033[0m",
               "blocked": "\033[93m⚠\033[0m"}.get(run.status, "?")
        console.step(f"{tag} {src.label:<20} {run.status} "
                     f"({len(run.results)} result(s), {len(run.queries)} query) "
                     f"{run.detail[:50]}")

    # 4b. reverse-image search on any input images (public-surface pivot)
    images = inv.input_context.get("images", [])
    if reverse_image != "off" and images and "public" in surfaces:
        from .reverse_image import reverse_search
        console.step("reverse-image lookups (SauceNAO/IQDB + prepared links)…")
        for rr in reverse_search(images, fetcher,
                                 os.environ.get("SAUCENAO_API_KEY", ""), live):
            inv.runs.append(rr)
            tag = {"ok": "\033[92m✓\033[0m", "planned": "\033[95m◐\033[0m",
                   "empty": "\033[90m∅\033[0m", "blocked": "\033[93m⚠\033[0m",
                   "error": "\033[91m✗\033[0m"}.get(rr.status, "?")
            console.step(f"{tag} {rr.label:<26} {rr.status} "
                         f"({len(rr.results)} match) {rr.detail[:44]}")

    # 5. correlate (first pass) so enrichment has entities to pivot on
    console.section("4 · Correlate & enrich")
    console.step("correlating entities into link graph …")
    correlate(inv)

    # 5a. let the model extend the static noise list for THIS run. NOISE_DOMAINS
    #     (entities.py) is a fast, offline baseline; it can't know every CDN,
    #     broker or platform. The agent judges the domains this run actually
    #     surfaced and flags the infra/platform ones (not the subject's own), so
    #     they are neither enriched nor graphed. Empty when no LLM — baseline holds.
    ai_noise: set = set()
    domain_vals = [e.value for e in inv.entities if e.kind == "domain"]
    if domain_vals:
        try:
            flagged = agent.classify_infra_domains(domain_vals, subject, ttype)
        except Exception:
            flagged = []
        if flagged:
            ai_noise = set(flagged)
            correlate(inv, extra_noise=ai_noise)   # drop them from the graph now
            console.step(f"  ai noise filter: dropped {len(ai_noise)} infra "
                         f"domain(s) the static list missed")
    inv._ai_noise = ai_noise   # reused by chat /refine and /focus re-correlation
    console.step(f"graph: {len(inv.entities)} node(s), {len(inv.edges)} edge(s)"
                 + (f", {inv.correlation_skipped} off-target result(s) not linked"
                    if inv.correlation_skipped else ""))

    # 5b. native enrichment — turn domains/IPs/BTC/handles into structured intel
    #     via keyless official APIs (crt.sh, DoH, Shodan InternetDB, Blockstream,
    #     GitHub, Reddit). Live-only, JSON reads only, onion never touched.
    if live and enrich != "off":
        from .enrich import run_enrichment
        console.step("enrichment (crt.sh/DNS/blockchain/handles)…")
        ers = run_enrichment(subject, ttype, inv, fetcher, extra_noise=ai_noise)
        if ers:
            for er in ers:
                inv.runs.append(er)
                tag = {"ok": "\033[92m✓\033[0m", "planned": "\033[95m◐\033[0m",
                       "empty": "\033[90m∅\033[0m",
                       "error": "\033[91m✗\033[0m"}.get(er.status, "?")
                console.step(f"{tag} {er.label:<34} {er.status} "
                             f"({len(er.results)} result)")
            # re-correlate so enrichment findings join the graph (same AI filter)
            correlate(inv, extra_noise=ai_noise)
            console.step(f"graph: {len(inv.entities)} node(s), "
                         f"{len(inv.edges)} edge(s)")
        else:
            console.step("  (no domain/ip/btc/handle to enrich)")

    # 5c. name -> handle resolution. The step that connects "Alex Marsh" to
    #     "AMarsh-Sec": not by deduction, but by checking whether an account
    #     PUBLICLY DECLARES the name. Only runs for person/name targets — for a
    #     username target the handle is the input, so there is nothing to
    #     resolve. Every candidate faces the same confirmation bar, so a
    #     same-handle stranger (github.com/amarsh is Maciej Jarczok, not Alex
    #     Marsh) is reported as explicitly NOT linked instead of as a finding.
    if live and enrich != "off" and ttype in ("name", "person"):
        from .handles import resolve_handles
        console.step("name↔handle confirmation …")
        hrun = resolve_handles(subject, inv.context or "", inv.all_results,
                               fetcher, aliases=getattr(inv, "aliases", None))
        inv.runs.append(hrun)
        n_conf = sum(1 for r in hrun.results
                     if (r.meta or {}).get("verdict") == "confirmed")
        tag = "\033[92m✓\033[0m" if n_conf else "\033[90m∅\033[0m"
        console.step(f"{tag} {hrun.label:<34} {n_conf} confirmed link(s)")
        if hrun.results:
            correlate(inv, extra_noise=ai_noise)

    # 6. synthesize
    console.section("5 · Synthesize & report")
    console.step("synthesizing analyst summary …")
    inv.synthesis = agent.synthesize(inv)
    # Ground the confidence in whether the identity actually resolved. The LLM
    # self-reports a confidence word, and left alone it will say "high" over a
    # summary that admits it found nothing — the exact failure that reads as a
    # hallucination. These caps let the summary state at most what the evidence
    # supports; they only ever lower confidence, never raise it.
    if inv.synthesis:
        ds = inv.deep_search or {}
        cands = ds.get("candidates") or []
        open_qs = ds.get("questions") or []
        notes = inv.synthesis.setdefault("risk_notes", [])
        conf = inv.synthesis.get("confidence")

        # Did the AI actually WRITE this run, or did the synthesis fall back to
        # the deterministic keyword summary? `agent.synthesize` tags the real
        # outcome in `ai_mode` (an available provider can still fail mid-call),
        # so trust that rather than re-deriving it from `agent.enabled` — which
        # was wrong exactly when a provider existed but its call degraded.
        if inv.synthesis.get("ai_mode") == "heuristic":
            notes.insert(
                0, "AI DEGRADED: the analyst write-up fell back to the "
                   "deterministic summary — the model was unavailable or its "
                   "call failed this run, so there was no AI reasoning over the "
                   "results. The search still ran and the name-accuracy guard "
                   "still applied, so nothing is misattributed — but read the "
                   "findings as raw matches and fix the provider key "
                   "(GROQ / GOOGLE / NVIDIA) for real analysis.")

        # (a) No candidate was actually CONFIRMED → the individual was never
        #     pinned down: either only same-name namesakes turned up, or the
        #     results describe the person's context (their school/employer) but
        #     never the person. Since `confirmed` now requires evidence that
        #     names the individual (see _grade), a run with nothing confirmed
        #     cannot be a medium/high result, however high the context matched.
        if cands:
            from .deepsearch import RESOLVED_OUTCOMES
            confirmed = any(c.get("outcome") in RESOLVED_OUTCOMES
                            for c in cands)
            if not confirmed and conf in ("medium", "high"):
                inv.synthesis["confidence"] = "low"
                conf = "low"
                notes.insert(
                    0, "Confidence floored to LOW: no candidate was confirmed to "
                       "be the target. The results either describe same-name "
                       "individuals or the target's context (e.g. their school), "
                       "not the person themselves — no personal data trace was "
                       "verified.")

        # (b) Open identity questions still outrank a 'high'.
        if open_qs and conf == "high":
            inv.synthesis["confidence"] = "medium"
            notes.insert(
                0, f"Confidence capped: {len(open_qs)} question(s) about the "
                   f"target's identity remain unanswered.")
    inv.guardrails = guard.summary()

    # 6. report
    html_path, json_path = render(inv, output_dir)
    inv._report_path = html_path  # for chat /last
    console.line("")
    console.head("Report ready")
    console.step(f"HTML : {html_path}")
    console.step(f"JSON : {json_path}")
    if make_pdf:
        try:
            from .report_pdf import render_pdf
            pdf_path = render_pdf(inv, output_dir)
            if pdf_path:
                inv._pdf_path = pdf_path
                console.step(f"PDF  : {pdf_path}")
            else:
                console.step("PDF  : skipped (install fpdf2 to enable: pip install fpdf2)")
        except Exception as exc:
            console.step(f"PDF  : failed ({type(exc).__name__})")
    if make_runbook:
        try:
            from .runbook import render_runbook
            rb = render_runbook(inv, output_dir)
            inv._runbook_path = rb
            console.step(f"RUNBOOK: {rb}")
        except Exception as exc:
            console.step(f"RUNBOOK: failed ({type(exc).__name__})")
    console.step(f"confidence: {inv.synthesis.get('confidence','?')} · "
                 f"guard blocks: {inv.guardrails.get('blocked',0)}")
    return inv
