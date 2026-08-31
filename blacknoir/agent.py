"""The AI agent brain.

Responsibilities:
  1. plan()      decide which sources fit the target (LLM if a key is present,
                 otherwise a deterministic heuristic router).
  2. vision()    describe/OCR an input image (Claude vision) — passed to inputs.
  3. synthesize()turn the correlated graph into an analyst summary, confidence,
                 pivots and next steps (LLM, with a templated fallback).

The agent is fully functional with NO API key: every LLM step has a heuristic
fallback so Black Noir is deterministic and offline-capable by default.
"""

from __future__ import annotations

import json
import os
from typing import Callable, Optional

from .config import REGISTRY, Source
from .entities import is_about_target
from .intent import heuristic_parse
from .llm import (LLM, available_providers, json_from_model,
                  multi_agent_enabled, panel_size)
from .models import Investigation

# Sources whose very presence is an actionable exposure keyed on the target's own
# identifier (email/handle) — a hit here concerns the individual regardless of
# whether the snippet repeats the name.
_ACTIONABLE_SOURCES = {"hibp", "dehashed", "intelx"}


def _applicable(source: Source, target_type: str, deep: bool = False) -> bool:
    """Can this source key on this target type at all?

    `good_for` is a statement about what the source indexes, so it binds the
    model's pick as much as the heuristic's. Showing the catalogue to a planner
    and then not enforcing it is how GitHub *code* search ran on the person name
    "Lam Wing Kit": twelve NEWS changelogs matched the tokens, none concerned a
    person, and the junk then seeded eight wasted handle-confirmation probes
    against `gnome`, `gphoto` and `adambard`. The registry already said
    `good_for=("username","email","domain","company","keyword")` — nothing
    consulted it on that path.
    """
    ttype = "name" if target_type in ("person",) else (target_type or "")
    # An unknown/absent type is not grounds to drop anything: filtering needs
    # something to filter *for*, and refusing every keyed source because we
    # could not type the target would silently empty the plan.
    if not ttype:
        return True
    if "any" in source.good_for or ttype in source.good_for:
        return True
    # A deep person/handle sweep still enlists the whole dark-web toolset: those
    # indexes are keyword-keyed, so a name is a usable query even though it is
    # not the identifier they file under.
    return deep and ttype in ("name", "username") and source.surface == "darkweb"


def _individual_linked_results(inv: Investigation) -> list:
    """Results that concern the PERSON, not just their context.

    Two ways to qualify: (a) an actionable-exposure source (breach/leak) that
    returned something, or (b) the text actually names the target or an alias/
    handle they supplied. `is_about_target` is called with an EMPTY context so a
    page that merely names the school/employer does NOT count — only the person.
    Everything else (school pages, directories, namesakes, DNS chrome) is
    context/noise and must not be sold as a finding.
    """
    aliases = list(getattr(inv, "aliases", None) or [])
    out = []
    for r in inv.all_results:
        if r.source in _ACTIONABLE_SOURCES and (r.title or r.snippet):
            out.append(r)
            continue
        text = f"{r.title} {r.snippet} {getattr(r, 'url', '')}"
        if is_about_target(text, inv.target, "", aliases):
            out.append(r)
    return out


_NO_TRACE_MARKERS = ("no personal data traces", "nothing exposed to remediate")


def _guard_no_trace_claim(findings, individual: list):
    """Strip a 'nothing was found' claim that the collected results contradict.

    A prompt rule is a request; this is the enforcement. The claim is uniquely
    load-bearing — an operator reads it as "you are clean" and stops — so it may
    only stand when the evidence list is genuinely empty. Where results named
    the subject, the claim is replaced by what was actually found, with the
    attribution caveat attached rather than the finding deleted.
    """
    items = [str(f) for f in (findings or []) if str(f).strip()]
    if not individual:
        return items
    kept = [f for f in items
            if not any(m in f.lower() for m in _NO_TRACE_MARKERS)]
    if len(kept) == len(items):
        return items
    replacement = (
        f"{len(individual)} result(s) carry the target's name; which person "
        "they concern is not yet confirmed (select a candidate with /focus to "
        "resolve). Their existence is a finding — the earlier 'no traces' "
        "wording contradicted the collected evidence and was removed.")
    return kept + [replacement]


class Agent:
    def __init__(self, provider: Optional[str] = None,
                 model: Optional[str] = None, use_llm: bool = True,
                 log: Optional[Callable[[str], None]] = None,
                 panel: bool = True,
                 panel_size_override: Optional[str] = None) -> None:
        self.llm = LLM(provider=provider, model=model, use_llm=use_llm, log=log)
        self.enabled = self.llm.enabled
        self.mode = self.llm.provider or "heuristic"
        self.model = self.llm.model
        self._log = log

        # Multi-agent panel: every OTHER keyed provider gets its own LLM, so a
        # search query is planned by all of them in parallel and the query sets
        # are unioned for wider recall. Ollama is excluded by default (local +
        # slow) unless BLACKNOIR_PANEL_OLLAMA is set or it is the chosen provider.
        self.panel: list[LLM] = []
        if use_llm and panel and self.enabled and multi_agent_enabled():
            inc_ollama = self.llm.provider == "ollama"
            cap = panel_size(panel_size_override)  # total models incl. primary
            for p in available_providers(include_ollama=inc_ollama):
                if len(self.panel) + 1 >= cap:  # +1 for the primary
                    break
                if p == self.llm.provider:
                    continue
                sub = LLM(provider=p, use_llm=True, log=None)
                if sub.enabled and sub.provider == p:
                    self.panel.append(sub)

        self.label = self.llm.label
        if self.panel:
            names = ", ".join(s.provider for s in self.panel)
            self.label = f"multi-agent [{self.llm.provider} + {names}]"
            if log:
                log(f"multi-agent panel: {self.llm.provider} (primary) + {names}")

    # -- low-level LLM call --------------------------------------------------

    def _complete(self, system: str, prompt: str, max_tokens: int = 1200,
                  llm: Optional[LLM] = None):
        return (llm or self.llm).complete_text(system, prompt, max_tokens)

    def classify_infra_domains(self, domains: list, subject: str,
                               subject_type: str = "person") -> list:
        """Decide which of these domains are infrastructure/platform NOISE.

        The static NOISE_DOMAINS set in entities.py is a fast, offline baseline;
        it can never know every CDN, data broker or platform. This lets the model
        judge the domains a specific run actually surfaced — flagging the ones
        that show up for *anyone* (search engines, socials, CDNs, cert/DNS hosts,
        brokers, reference sites) while keeping anything that could be the
        subject's own site/blog/portfolio. Returns a subset of `domains`.

        Returns [] when there is no LLM or on any error — the static baseline
        still applies, so this only ever *adds* precision, never removes it.
        """
        if not self.enabled or not domains:
            return []
        uniq = list(dict.fromkeys(
            d.strip().lower() for d in domains if d and isinstance(d, str)))[:40]
        if not uniq:
            return []
        prompt = (
            f"While researching the {subject_type} '{subject}', these domains "
            f"appeared in search results:\n{json.dumps(uniq)}\n\n"
            "Return ONLY the domains that are NOT owned by or specific to this "
            "subject — i.e. search engines, social/media platforms, CDNs, "
            "certificate/DNS infrastructure, data-broker or generic reference "
            "sites (things that appear for anyone, not a personal footprint). "
            "KEEP any domain that could plausibly be the subject's own "
            "site/blog/portfolio/company. Use the domains exactly as given. "
            'Respond ONLY as JSON: {"infra":["domain", ...]}.')
        out = self._complete(
            "You classify domains as infrastructure/platform noise vs the "
            "subject's own footprint. Output strict JSON only.", prompt, 500)
        if not out:
            return []
        try:
            data = json.loads(out[out.find("{"):out.rfind("}") + 1])
            allow = set(uniq)
            return [d.strip().lower() for d in (data.get("infra") or [])
                    if isinstance(d, str) and d.strip().lower() in allow]
        except Exception:
            return []

    @property
    def panel_n(self) -> int:
        """Models that answer a fan-out — the primary plus the panel."""
        return 1 + len(self.panel) if self.enabled else 0

    def fanout_json(self, system: str, prompt: str, max_tokens: int = 1200,
                    *, timeout: Optional[float] = None,
                    label: str = "") -> list[dict]:
        """Ask every panel model the same question; return the parsed answers.

        The search half of the multi-agent design. Planning fans out to widen
        recall (union the query sets); the search steps fan out to make a
        JUDGEMENT robust — which results are the same person, which belong to
        a candidate. Those are exactly the calls where one model's bad round
        silently decides the whole investigation, so they are voted rather
        than trusted.

        Answers that fail to parse are dropped, not substituted, so a caller
        can tell "nobody answered" (empty list) from "the panel agrees on
        nothing" (answers present, votes empty). One slow provider can never
        stall a run: whatever arrived by the deadline is what gets voted on.
        """
        if not self.enabled:
            return []
        llms = [self.llm] + self.panel
        if len(llms) == 1:
            data = json_from_model(self._complete(system, prompt, max_tokens))
            return [data] if isinstance(data, dict) else []

        import concurrent.futures as cf
        budget = timeout if timeout is not None else float(
            os.environ.get("BLACKNOIR_PANEL_TIMEOUT", "45"))
        out: list[dict] = []

        def _ask(lm: LLM):
            return json_from_model(
                self._complete(system, prompt, max_tokens, llm=lm))

        with cf.ThreadPoolExecutor(max_workers=min(8, len(llms))) as ex:
            futs = {ex.submit(_ask, lm): lm for lm in llms}
            try:
                for fut in cf.as_completed(futs, timeout=budget):
                    try:
                        d = fut.result()
                    except Exception:
                        d = None
                    if isinstance(d, dict) and d:
                        out.append(d)
            except cf.TimeoutError:
                slow = [futs[f].provider for f in futs if not f.done()]
                if self._log and slow:
                    self._log(f"{label or 'panel'}: dropped slow provider(s) "
                              f"{', '.join(p for p in slow if p)} "
                              f"after {budget:.0f}s")
                for f in futs:
                    f.cancel()
        return out

    # -- natural-language target parsing -------------------------------------

    def parse_target(self, raw: str, has_images: bool,
                     image_hint: str = "") -> dict:
        """Extract {subject, subject_type, depth, is_question} from an
        instruction like 'This is Jensen Huang, search every secret detail'."""
        if self.enabled:
            prompt = (
                f"Instruction: {raw!r}\n"
                f"Images attached: {has_images}. Image summary: {image_hint[:600]}\n\n"
                "Extract the OSINT search subject. Respond ONLY with JSON: "
                '{"subject":"the specific entity to search — a name, username, '
                'email, domain or company; if the text names someone, use that '
                'name properly cased; if only an image and no name, use a short '
                'descriptive label","subject_type":"person|name|username|handle'
                '|email|domain|company|phone|ip|btc|onion — pick the machine-'
                'readable type when the subject IS one (a phone number is '
                '\'phone\', not \'person\'); there is no \'other\'",'
                '"depth":"normal|deep","is_question":true|false,'
                '"context":"any qualifier the user gave that distinguishes this '
                'subject from people/things with the same name — industry, '
                'employer, role, location, affiliation. Keep it as short '
                'search-friendly keywords, NOT a sentence. Empty string if none.",'
                '"aliases":["every OTHER name the instruction gives for the SAME '
                'subject — legal name, romanization, native-script name, maiden '
                'name, handle. Names only, no qualifiers. Empty list if none."]}. '
                "Strip command words ('search', 'find', 'every secret detail') "
                "from the subject, but NEVER discard a qualifier — put it in "
                "'context'. Examples:\n"
                "  'find \"Li Wei\" whose full name is \"李伟\" or \"Lee Wai\" "
                "from Acme' -> subject 'Li Wei', aliases ['李伟','Lee Wai'], "
                "context 'Acme'\n"
                "  'find A. Rivera who is from the shipping industry' -> "
                "subject 'A. Rivera', context 'shipping industry'\n"
                "  'search K. Novak working at a Berlin games studio' -> "
                "subject 'K. Novak', context 'Berlin games studio'\n"
                "  'look up example-corp.com' -> subject 'example-corp.com', "
                "context ''\n"
                "depth is 'deep' when the user asks for everything/all/comprehensive.")
            # Budget covers a reasoning model that narrates before answering:
            # at 400 the narration alone consumed the allowance and the JSON was
            # truncated mid-object, silently dropping the run to heuristics.
            out = self._complete(
                "You extract OSINT search targets. Output strict JSON only — "
                "no preamble, no explanation, no reasoning.",
                prompt, 900)
            if out:
                try:
                    from .llm import json_from_model
                    data = json_from_model(out) or {}
                    if data.get("subject"):
                        data.setdefault("depth", "normal")
                        data.setdefault("subject_type", "name")
                        data.setdefault("is_question", False)
                        data["raw"] = raw
                        data["mode"] = "llm"
                        # never let a model omission silently drop the qualifier
                        if not (data.get("context") or "").strip():
                            from .intent import extract_context
                            data["context"] = extract_context(raw, data["subject"])
                        # same for alternate names: a dropped native-script name
                        # is usually the most searchable form the user gave.
                        aliases = data.get("aliases")
                        if not isinstance(aliases, list) or not aliases:
                            from .intent import extract_aliases
                            aliases = extract_aliases(raw, data["subject"])
                        data["aliases"] = [str(a).strip() for a in aliases
                                           if str(a).strip()][:6]
                        return data
                    self._log_note("target parse: model returned no 'subject' "
                                   "— using the heuristic parser")
                except Exception as exc:
                    self._log_note(f"target parse: unusable model output "
                                   f"({type(exc).__name__}) — using the "
                                   f"heuristic parser")
            elif self.enabled:
                why = getattr(self.llm, "last_error", None) or "no response"
                self._log_note(f"target parse: model call failed ({why[:80]}) "
                               f"— using the heuristic parser")
        return heuristic_parse(raw, has_images)

    def _log_note(self, msg: str) -> None:
        """Say why a model-backed step degraded. A silent fallback to the
        heuristic parser is how a whole investigation quietly loses the
        qualifier and the alternate names the user actually supplied."""
        if getattr(self, "_log", None):
            self._log(msg)

    # -- vision --------------------------------------------------------------

    def vision(self, image_b64: str, media_type: str, filename: str) -> dict:
        """Return {'analysis': str, 'extracted': {kind: [values]}}.

        The extracted identifiers are injected straight into the entity graph,
        so a signature/watermark/handle read from the image becomes a real
        pivot instead of being buried in prose.
        """
        if not self.enabled:
            return {"analysis": "(vision disabled: configure an LLM provider "
                    "to analyze images)", "extracted": {}}
        prompt = (
            f"This image ({filename}) is OSINT evidence (often artwork). "
            "Read every visible mark: signatures, watermarks, usernames, "
            "handles, URLs, emails, platform tags (e.g. 'DA:', 'IG:'), onion "
            "addresses. Also classify what the image mainly is.\n\n"
            "Then produce LEADS: ranked, checkable hypotheses about the image's "
            "origin, each with a confidence 0.0-1.0 and the evidence it rests "
            "on.\n"
            "RULES for leads (important):\n"
            "  * A lead must cite something VISIBLE — a handle, watermark, "
            "logo, uniform, badge, signage, landmark, architecture, visible "
            "screens, document layout.\n"
            "  * NEVER identify or name a real person from their face or "
            "appearance, and never infer who someone is from physical "
            "characteristics. Facial appearance is not evidence. This bans "
            "face-to-name inference ONLY.\n"
            "  * It does NOT excuse you from analysing everything else. A "
            "photo OF a person is still full of evidence: transcribe any "
            "signage (including non-Latin scripts, and translate it), read "
            "visible screens, and reason about the interior — ceiling and "
            "lighting type, furniture, room layout, floor plan — plus "
            "clothing, lanyards, badges and devices. Say what they suggest "
            "about the PLACE and SETTING (office, campus, lab, home, transit; "
            "and which region or language area). Those are proper leads: give "
            "them with confidence scores.\n"
            "  * Use identifiability 'face-only' ONLY when the frame is "
            "genuinely featureless — a plain or blurred background with no "
            "signage, no architecture and no objects. If there is a room "
            "around the person, it is 'contextual', not 'face-only'.\n"
            "  * Prefer 'this watermark belongs to an account named X' over "
            "'this is X'. State what would confirm it.\n"
            "  * Do not inflate confidence. A generic office interior is ~0.2, "
            "a legible sign naming an organisation is ~0.7, a unique handle "
            "plus a matching domain is ~0.8.\n\n"
            "Respond ONLY with JSON:\n"
            '{"subject_type":"person|artwork|document|screenshot|logo|scene|other",'
            '"description":"one factual sentence about the image",'
            '"transcription":"all visible text verbatim",'
            '"names":[],"usernames":[],"handles":[],"domains":[],'
            '"emails":[],"watermarks":[],"platforms":[],'
            '"identifiability":"marks|contextual|face-only|none",'
            '"leads":[{"hypothesis":"","basis":"the visible evidence",'
            '"confidence":0.0,"how_to_verify":""}]}\n'
            "Use exact strings as they appear. Empty arrays if none.")
        out = self.llm.complete_vision(
            "You are a meticulous OSINT image analyst. Output strict JSON only.",
            prompt, image_b64, media_type, 900)
        return self._parse_vision(out)

    @staticmethod
    def _parse_vision(out) -> dict:
        if not out:
            return {"analysis": "(vision call failed)", "extracted": {}}
        if out.lstrip().startswith("(vision"):  # disabled/unsupported marker
            return {"analysis": out, "extracted": {}}
        keys = ("names", "usernames", "handles", "domains", "emails",
                "watermarks", "platforms")
        try:
            data = json.loads(out[out.find("{"):out.rfind("}") + 1])
        except Exception:
            return {"analysis": out[:1200], "extracted": {}}
        extracted = {k: [str(v) for v in (data.get(k) or []) if v] for k in keys}
        subject_type = str(data.get("subject_type", "") or "other")

        # Ranked, evidence-backed leads. Anything without a stated basis is
        # dropped: an unsupported hypothesis is a guess wearing a score.
        leads = []
        for L in (data.get("leads") or []):
            if not isinstance(L, dict):
                continue
            hyp, basis = str(L.get("hypothesis") or "").strip(), \
                str(L.get("basis") or "").strip()
            if not hyp or not basis:
                continue
            try:
                conf = max(0.0, min(1.0, float(L.get("confidence") or 0.0)))
            except (TypeError, ValueError):
                conf = 0.0
            leads.append({"hypothesis": hyp[:200], "basis": basis[:200],
                          "confidence": conf,
                          "how_to_verify": str(L.get("how_to_verify") or "")[:200]})
        leads.sort(key=lambda x: -x["confidence"])
        identifiability = str(data.get("identifiability", "") or "none")

        lines = []
        if data.get("transcription"):
            lines.append("Text: " + str(data["transcription"]))
        if data.get("description"):
            lines.append(str(data["description"]))
        for k in keys:
            if extracted.get(k):
                lines.append(f"{k}: " + ", ".join(extracted[k]))
        if leads:
            lines.append("Leads (ranked):")
            for L in leads:
                lines.append(f"  [{L['confidence']:.2f}] {L['hypothesis']} "
                             f"— basis: {L['basis']}")
        elif identifiability == "face-only":
            lines.append("Leads: none — the only identifying content is a "
                         "face. Black Noir does not attribute identity from "
                         "facial appearance; use the prepared reverse-image "
                         "links with proper authorization instead.")
        return {"analysis": "\n".join(lines) or "(no text found)",
                "extracted": extracted, "subject_type": subject_type,
                "leads": leads, "identifiability": identifiability}

    # -- planning ------------------------------------------------------------

    def plan(self, inv: Investigation, surfaces: list[str],
             input_summary: str, depth: str = "normal") -> dict:
        candidates = [s for s in REGISTRY.values() if s.surface in surfaces]
        if self.enabled:
            plans = self._fanout_plans(inv, candidates, input_summary, depth)
            if len(plans) == 1:
                return plans[0]
            if plans:
                return self._merge_plans(plans, candidates, inv, depth)
        return self._plan_heuristic(inv, candidates, depth)

    def _fanout_plans(self, inv, candidates, input_summary, depth) -> list[dict]:
        """Plan with the primary LLM and every panel member concurrently.

        A per-fan-out deadline means one slow/rate-limited provider (some free
        endpoints take a minute) can never stall the search — whatever plans
        arrived in time are merged, the stragglers are dropped.
        """
        llms = [self.llm] + self.panel
        if len(llms) == 1:
            p = self._plan_llm(inv, candidates, input_summary, depth, self.llm)
            return [p] if p else []
        import concurrent.futures as cf
        timeout = float(os.environ.get("BLACKNOIR_PLAN_TIMEOUT", "30"))
        plans: list[dict] = []
        with cf.ThreadPoolExecutor(max_workers=min(8, len(llms))) as ex:
            futs = {ex.submit(self._plan_llm, inv, candidates, input_summary,
                              depth, lm): lm for lm in llms}
            try:
                for fut in cf.as_completed(futs, timeout=timeout):
                    try:
                        p = fut.result()
                    except Exception:
                        p = None
                    if p:
                        plans.append(p)
            except cf.TimeoutError:
                slow = [futs[f].provider for f in futs if not f.done()]
                if self._log and slow:
                    self._log(f"planning: dropped slow provider(s) "
                              f"{', '.join(slow)} after {timeout:.0f}s")
                for f in futs:
                    f.cancel()
        return plans

    def _merge_plans(self, plans: list[dict], candidates, inv,
                     depth: str = "normal") -> dict:
        """Union the source picks and de-duplicate the query sets across models
        — more diverse queries means higher recall than any single model.

        Unioning widens recall, which also means one model's inapplicable pick
        is enough to enlist a source none of the others wanted. `_applicable`
        is applied here rather than trusting the union.
        """
        by_key = {c.key: c for c in candidates}
        deep = depth == "deep"
        selected, seen_keys, dropped = [], set(), []
        queries, seen_q = [], set()
        for p in plans:
            for s in p.get("selected", []):
                k = s.get("key")
                if k not in by_key or k in seen_keys:
                    continue
                seen_keys.add(k)
                if not _applicable(by_key[k],
                                   getattr(inv, "target_type", ""), deep):
                    dropped.append(by_key[k].label)
                    continue
                selected.append(s)
            for q in p.get("queries", []):
                ql = (q or "").strip()
                if ql and ql.lower() not in seen_q:
                    seen_q.add(ql.lower())
                    queries.append(ql)
        if not selected:
            return self._plan_heuristic(inv, candidates, depth)
        return {
            "mode": f"multi-agent×{len(plans)}",
            "selected": selected,
            "queries": queries[:14] or [inv.target],
            "reasoning": (f"Union of {len(plans)} model plans: {len(selected)} "
                          f"source(s) any model chose, {len(queries)} "
                          "de-duplicated queries for wider recall."
                          + (f" Dropped {len(dropped)} pick(s) that cannot key "
                             f"on a '{getattr(inv, 'target_type', '')}' target: "
                             f"{', '.join(dropped)}." if dropped else "")),
        }

    def _plan_llm(self, inv, candidates, input_summary, depth="normal", llm=None):
        catalog = [
            {"key": s.key, "label": s.label, "surface": s.surface,
             "good_for": list(s.good_for), "available": s.available}
            for s in candidates
        ]
        deep = depth == "deep"
        ctx = (inv.context or "").strip()
        prompt = (
            f"TARGET: {inv.target}\nTYPE: {inv.target_type}\nDEPTH: {depth}\n"
            + (f"DISAMBIGUATING CONTEXT: {ctx}\n" if ctx else "")
            + (f"ORIGINAL INSTRUCTION: {inv.raw!r}\n" if inv.raw else "")
            + f"SURFACES: {', '.join(inv.surfaces)}\n"
            f"INPUT CONTEXT:\n{input_summary[:3000]}\n\n"
            f"AVAILABLE SOURCES (JSON):\n{json.dumps(catalog)}\n\n"
            "Choose the sources worth querying for this target and order them "
            "by expected value. Also craft strong search QUERIES using PUBLIC "
            "OSINT angles only (biography, profiles, affiliations, interviews, "
            "public records, news). For a PERSON, cover identity, roles, "
            "organizations, social handles, and contact surfaces.\n"
            "QUERY RULES (strict — violating these makes the search fail):\n"
            "  * NO phrase quotes and NO operators (site:, OR, intitle:, -). "
            "Free-tier SERP APIs reject them with an error.\n"
            + (f"  * HARD CONSTRAINT: put the disambiguating context ({ctx}) or a "
               f"specific identifier (phone/handle) in EVERY query. Do NOT emit "
               f"any bare name-only query — it returns same-name university / "
               f"overseas namesakes the constraint is meant to exclude.\n"
               if ctx else "")
            + f"Produce {'8-10' if deep else '3-5'} queries. "
            "Respond ONLY with JSON: "
            '{"selected":[{"key":"...","why":"..."}],"queries":["..."],'
            '"reasoning":"..."}. Only public information; never suggest fetching '
            "onion links, downloading files, or accessing private/non-public data.")
        out = self._complete(
            "You are an OSINT planning agent. Output strict JSON only.", prompt,
            900, llm=llm)
        if not out:
            return None
        try:
            data = json.loads(out[out.find("{"):out.rfind("}") + 1])
            by_key = {c.key: c for c in candidates}
            data["selected"] = [
                s for s in data.get("selected", [])
                if s.get("key") in by_key
                and _applicable(by_key[s["key"]], inv.target_type, deep)]
            if not data["selected"]:
                return None
            _ctx = (inv.context or "").strip()
            data.setdefault("queries",
                            [f"{inv.target} {_ctx}".strip() if _ctx
                             else inv.target])
            data["mode"] = "llm"
            return data
        except Exception:
            return None

    def _plan_heuristic(self, inv, candidates, depth="normal") -> dict:
        raw_type = inv.target_type
        ttype = "name" if raw_type in ("person",) else raw_type
        deep = depth == "deep"
        selected = []
        for s in candidates:
            if not s.available:
                continue
            # Shared with the LLM planning paths so both routes agree on what a
            # source can key on (deep person/handle sweeps still enlist the
            # keyword-indexed dark-web toolset).
            if _applicable(s, raw_type, deep):
                selected.append({"key": s.key,
                                 "why": f"matches '{ttype}'" + (" (deep)" if deep else "")})
        # Every public engine stays on the list even when it cannot key on this
        # target: the connector then declines it with a stated reason, and the
        # report's "skipped — needs a domain/IP target" row is how an operator
        # sees which modules sat out and why. Filtering here would delete that
        # explanation rather than the wasted query.
        for s in candidates:
            if s.surface == "public" and s.available \
                    and s.key not in {x["key"] for x in selected}:
                selected.append({"key": s.key, "why": "baseline web coverage"})
        queries = self._build_queries(inv, deep)
        return {"mode": "heuristic", "selected": selected, "queries": queries,
                "reasoning": (f"Routed by type '{ttype}' (depth={depth}): public "
                              "engines for broad coverage, messenger-OSINT for "
                              "handles, onion indexes for leaks, breach sources "
                              "for emails. Public sources only.")}

    @staticmethod
    def _build_queries(inv: Investigation, deep: bool = False) -> list[str]:
        """Plain-keyword queries, qualifier-first.

        No phrase quotes and no `site:` operators: free-tier SERP APIs reject
        those outright (Serper answers 400 "Query pattern not allowed for free
        accounts"), which used to kill the whole source on its first query.
        The disambiguating context is appended to every variation, because a
        bare common name returns namesakes rather than the target.
        """
        t = inv.target
        ctx = (inv.context or "").strip()
        # When a hard constraint (context) is supplied, every public query is
        # context-qualified — a bare name-only query just pulls same-name
        # university/overseas namesakes, which Phase 5 then has to sort back out.
        # Without a constraint the bare name is all we have.
        q = ([f"{t} {ctx}"] if ctx else [t])

        def w(*suffixes: str) -> list[str]:
            """One variation per suffix, context-qualified when available."""
            out = []
            for s in suffixes:
                out.append(f"{t} {ctx} {s}".strip() if ctx else f"{t} {s}".strip())
            return out

        if inv.target_type in ("name", "person"):
            q += w("LinkedIn", "profile", "biography", "interview", "company")
            if deep:
                q += w("education", "contact email", "social media", "news",
                       "conference speaker", "github")
        if inv.target_type in ("username", "handle"):
            q += w("profile", "github", "telegram", "reddit")
            if deep:
                q += w("leak", "breach", "instagram", "twitter")
        if inv.target_type == "email":
            q += w("breach", "dump", "profile")
        if inv.target_type in ("domain", "company"):
            q += w("database leak", "employees", "data breach", "about")
        return list(dict.fromkeys(x for x in q if x))

    # -- synthesis -----------------------------------------------------------

    def synthesize(self, inv: Investigation) -> dict:
        # Tag which path actually produced the write-up. `self.enabled` only
        # says a provider was configured — the LLM call can still fail (rate
        # limit, dead model) and silently fall back to the deterministic
        # summary. The report banner keys on THIS, so it must reflect what
        # really ran, not merely what was available.
        if self.enabled:
            out = self._synth_llm(inv)
            if out:
                if isinstance(out, dict):
                    out["ai_mode"] = "ai"
                return out
        out = self._synth_heuristic(inv)
        if isinstance(out, dict):
            out["ai_mode"] = "heuristic"
        return out

    def _synth_llm(self, inv: Investigation):
        results = [
            {"source": r.source, "surface": r.surface,
             "title": r.title[:160], "snippet": r.snippet[:200],
             "onion": r.is_onion}
            for r in inv.all_results[:60]
        ]
        entities = [{"value": e.value, "kind": e.kind, "weight": e.weight}
                    for e in inv.entities]
        # Sources that were refused rather than genuinely empty. Without this
        # the model reads a blocked engine as evidence of absence and reports
        # "no footprint" for a target it simply never managed to search.
        failed = [{"source": r.label, "status": r.status, "why": r.detail[:120]}
                  for r in inv.runs if r.status in ("blocked", "error", "skipped")]
        ctx = (inv.context or "").strip()
        # Whether the deep loop actually tied results to the target, so the
        # narrative can't assert a confirmed identity the search never reached.
        ds = getattr(inv, "deep_search", None) or {}
        _cands = ds.get("candidates") or []
        # Consult the shared set, not the bare string "confirmed": the /focus
        # path resolves an identity as "operator-confirmed", and matching only
        # the literal made this False on EVERY run — which hard-instructed the
        # model below to deny findings the loop had actually corroborated.
        from .deepsearch import RESOLVED_OUTCOMES
        _resolved = any(c.get("outcome") in RESOLVED_OUTCOMES for c in _cands)
        _by_operator = any(c.get("outcome") == "operator-confirmed"
                           for c in _cands)
        _top_match = max((c.get("context_match") or 0.0 for c in _cands),
                         default=None)
        # Separate results that actually concern the INDIVIDUAL (impactful,
        # actionable) from context/namesake noise (the person's school, generic
        # directories). Findings must be built from the former; when it is empty
        # the honest headline is "nothing exposed", not a wall of school pages.
        individual = _individual_linked_results(inv)
        indiv_payload = [{"source": r.source, "title": r.title[:160],
                          "snippet": r.snippet[:200]} for r in individual[:25]]
        # Built as a statement, not a nested ternary inside the prompt f-string:
        # this instruction decides whether the model may report findings at all,
        # so it has to be legible enough to check by eye.
        identity_line = ""
        if _cands:
            score = (f" (best candidate match {_top_match:.2f}/1.0; a candidate "
                     f"must reach 0.25 to count as this target)"
                     if _top_match is not None else "")
            if _by_operator:
                verdict = (
                    "CONFIRMED. The operator personally identified which "
                    "candidate is the target, so WHO this is is settled — do "
                    "not second-guess it or describe the confirmed candidate as "
                    "an unlinked namesake. Report what was and was not found "
                    "about THAT person, and let confidence reflect the weight of "
                    "evidence, not doubt about the identification.")
            elif _resolved:
                verdict = (
                    "CONFIRMED. Corroborating evidence names this individual; "
                    "report findings about that person.")
            elif individual:
                # The distinction this branch exists for: pages carrying the
                # name were found, but WHICH person they are is still open.
                # Collapsing that into "NOT CONFIRMED, you found nothing" is
                # what made a run report 'nothing exposed to remediate' while
                # its own candidate list held a school page naming the target.
                # Unresolved identity is a reason not to ATTRIBUTE the pages,
                # never a reason to deny they exist.
                verdict = (
                    f"UNRESOLVED. {len(individual)} result(s) carry this name, "
                    "but which person they belong to is not settled — the "
                    "operator has not selected a candidate yet. Report those "
                    "results as name-matches awaiting confirmation: say what "
                    "was found and that attribution is pending. Do NOT state "
                    "that nothing was found, and do NOT assert any biography, "
                    "school, job or contact detail as belonging to the target. "
                    "Set confidence to 'low'.")
            else:
                verdict = (
                    "NOT CONFIRMED. You did NOT find the target: state plainly "
                    "that the results are same-name individuals who could not be "
                    "linked to the target, do NOT present any biography, school, "
                    "job or contact detail as belonging to the target, and set "
                    "confidence to 'low'.")
            identity_line = f"IDENTITY RESOLUTION: {verdict}{score}\n"

        # The zero-findings sentence is a claim about the world ("nothing is
        # exposed"), so which branch applies is decided here from the actual
        # count rather than left to the model to infer from the prompt. Offered
        # as a permitted option when it was not, it gets chosen — that is how a
        # run with nine name-matching results reported nothing exposed.
        findings_rule = (
            "FINDINGS RULE: build 'key_findings' ONLY from individual-linked "
            "results — a breach/leak hit, a reused handle, or a page that names "
            "the person. Do NOT list generic organisation or context pages (a "
            "school's own website, a directory listing, DNS/domain chrome) as "
            "findings; order the real ones by impact (leaked credentials or "
            "contact first).\n")
        if individual:
            findings_rule += (
                f"There ARE {len(individual)} individual-linked result(s), so "
                "'key_findings' MUST describe them and MUST NOT say that "
                "nothing was found or that there is nothing to remediate. If "
                "attribution to the target is unconfirmed, say the pages carry "
                "the name and that confirming which person they concern is the "
                "outstanding step — that is a finding, not an absence.\n")
        else:
            findings_rule += (
                "There are ZERO individual-linked results, so 'key_findings' "
                "must be exactly ['No personal data traces were found for this "
                "individual - nothing exposed to remediate.'] and 'confidence' "
                "must be 'low'."
                + (" Because sources failed, 'risk_notes' must also state that "
                   "the sweep was incomplete, so this is not evidence of "
                   "absence.\n" if failed else "\n"))

        prompt = (
            f"TARGET: {inv.target} ({inv.target_type})\n"
            + (f"DISAMBIGUATING CONTEXT: {ctx}\n" if ctx else "")
            + identity_line
            + f"ENTITIES: {json.dumps(entities)[:3000]}\n"
            f"RESULTS: {json.dumps(results)[:6000]}\n"
            f"SOURCES THAT FAILED (not searched — absence of results here is "
            f"NOT evidence of absence): {json.dumps(failed)[:1200]}\n"
            f"OFF-TARGET RESULTS DISCARDED (same name, different person): "
            f"{inv.correlation_skipped}\n"
            + (f"INDIVIDUAL-LINKED RESULTS ({len(individual)} of "
               f"{len(inv.all_results)} — the rest are context/namesake noise): "
               f"{json.dumps(indiv_payload)[:3000]}\n"
               if inv.all_results else "")
            + findings_rule
            + "Write an OSINT analyst summary. Respond ONLY as JSON: "
            '{"summary":"...","confidence":"low|medium|high",'
            '"key_findings":["..."],"pivots":["..."],"next_steps":["..."],'
            '"risk_notes":["..."]}. Base claims only on the data.\n'
            + (f"Judge every finding against the context ({ctx}): results about "
               f"a different person with the same name are NOT findings about "
               f"this target — say so explicitly rather than reporting them.\n"
               if ctx else "")
            + "Distinguish 'we found nothing' from 'we could not search': if "
            "sources failed, say the search was incomplete instead of "
            "concluding the target has no footprint. Recommend no "
            "action that involves visiting onion sites or downloading files.")
        out = self._complete(
            "You are a senior OSINT analyst. Output strict JSON only.", prompt, 1400)
        if not out:
            return None
        try:
            data = json.loads(out[out.find("{"):out.rfind("}") + 1])
            data["mode"] = "llm"
            data["key_findings"] = _guard_no_trace_claim(
                data.get("key_findings"), individual)
            return data
        except Exception:
            return None

    def _synth_heuristic(self, inv: Investigation) -> dict:
        results = inv.all_results
        by_surface = {"public": 0, "darkweb": 0}
        for r in results:
            by_surface[r.surface] = by_surface.get(r.surface, 0) + 1
        onion_hits = [r for r in results if r.is_onion]
        breach_hits = [r for r in results if r.source in ("hibp", "dehashed")]
        top_entities = sorted(inv.entities, key=lambda e: -e.weight)[:8]
        individual = _individual_linked_results(inv)

        findings = []
        if breach_hits:
            findings.append(f"{len(breach_hits)} breach record(s) referencing the target.")
        if individual:
            findings.append(f"{len(individual)} result(s) directly reference the "
                            f"individual (of {len(results)} collected).")
        else:
            findings.append("No personal data traces were found for this "
                            "individual — the results are context (e.g. their "
                            "organisation) or same-name namesakes, not the person.")
        if onion_hits:
            findings.append(f"{len(onion_hits)} onion index reference(s) (links kept "
                            "as metadata; not visited).")
        if individual and len(top_entities) > 1:
            findings.append("Correlated identifiers: " +
                            ", ".join(f"{e.value} ({e.kind})" for e in top_entities[1:6]))

        # A person is only 'found' via a breach hit or a result that names them;
        # a pile of school/namesake pages is not corroboration.
        confidence = "low"
        if breach_hits or (individual and len(results) >= 8):
            confidence = "medium"
        if breach_hits and onion_hits and by_surface["public"] >= 3:
            confidence = "high"

        return {
            "mode": "heuristic",
            "summary": (f"Collected {len(results)} results across "
                        f"{len([r for r in inv.runs if r.status=='ok'])} live sources "
                        f"for {inv.target_type} target '{inv.target}'. "
                        f"{len(inv.entities)-1} correlated identifier(s) mapped into "
                        "the link graph."),
            "confidence": confidence,
            "key_findings": findings,
            "pivots": [f"{e.value} ({e.kind})" for e in top_entities[1:6]],
            "next_steps": [
                "Review the entity graph for the highest-weight nodes.",
                "If breach data appeared, rotate/monitor the exposed accounts.",
                "Set an LLM provider key (e.g. GOOGLE_API_KEY) for AI planning "
                "+ image vision.",
                "Corroborate onion-index metadata via trusted analysts — do not "
                "visit onion links from this tool.",
            ],
            "risk_notes": [
                "Dark-web results are index metadata only; no onion service was "
                "contacted and nothing was downloaded.",
            ],
        }
