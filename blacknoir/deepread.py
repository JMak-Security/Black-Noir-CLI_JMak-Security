"""Detective read: fetch and READ the pages that name the target, in full.

Black Noir's default posture is index-metadata-only — it reads search *snippets*
and never opens a page. That is safe, but it is also the exact thing that (a)
caused the snippet-splice fabrications (a snippet stitches non-adjacent lines, so
'Kin-ball … Lam Wing Kit' looked like one fact) and (b) capped recall far below
what Google's own AI Mode does, because AI Mode opens the pages and reads them.

This module closes that gap on demand: given the URLs already found to NAME the
target, it fetches each, pulls the text *around* every mention of the name, and
lets the model extract facts grounded in the real page — not spliced snippets.
It is opt-in (the operator triggers it), because it changes the no-follow
posture: it DOES open pages. Everything it reads is treated as untrusted text.
"""

from __future__ import annotations

import re
from typing import Callable, Optional


def _log(cb: Optional[Callable[[str], None]], msg: str) -> None:
    if cb:
        cb(msg)


def _windows(text: str, names: list[str], radius: int = 260,
             limit: int = 8) -> list[str]:
    """Text spans around each mention of a name — the part actually about them."""
    out: list[str] = []
    for n in names:
        n = (n or "").strip()
        if len(n) < 2:
            continue
        for m in re.finditer(re.escape(n), text, re.I):
            s = max(0, m.start() - radius)
            e = min(len(text), m.end() + radius)
            frag = re.sub(r"\s+", " ", text[s:e]).strip()
            if frag and frag not in out:
                out.append(frag)
            if len(out) >= limit:
                return out
    return out


def read_pages(target: str, aliases: list, context: str, urls: list,
               fetcher, agent, log=None, cap: int = 8) -> tuple:
    """Fetch + read the given URLs; return (read_records, grounded_facts).

    read_records: [{url, title, named(bool), excerpt}] for reporting.
    grounded_facts: model-extracted facts, each supported by page text that
    sits next to the target's name (never across unrelated lines).
    """
    from .webfetch import fetch_page

    names = [target] + [a for a in (aliases or []) if a]
    seen: set = set()
    read: list = []
    for url in urls:
        if not url or url in seen:
            continue
        seen.add(url)
        if len(read) >= cap:
            break
        page = fetch_page(url, fetcher)
        if not page.get("ok"):
            _log(log, f"read: {url[:60]} — skipped ({page.get('note', 'no text')})")
            continue
        text = page.get("text", "") or ""
        wins = _windows(text, names)
        named = bool(wins)
        _log(log, f"read: {url[:60]} — {'NAMES the target' if named else 'fetched, no name match'}"
                  f" ({len(text)} chars)")
        read.append({"url": url, "title": page.get("title") or "",
                     "named": named,
                     "excerpt": " … ".join(wins)[:1800] if wins else ""})

    named_pages = [r for r in read if r["named"]]
    if not named_pages:
        return read, []

    if not (agent and getattr(agent, "enabled", False)):
        return read, []   # no model to extract; the excerpts still show in-report

    corpus = "\n\n".join(
        f"URL: {r['url']}\nTITLE: {r['title']}\nTEXT (around the name): {r['excerpt']}"
        for r in named_pages)[:6000]
    prompt = (
        f'TARGET: "{target}"\n'
        + (f'ALSO KNOWN AS: {", ".join(a for a in (aliases or []) if a)}\n'
           if aliases else "")
        + (f'CONTEXT: "{context}"\n' if context else "")
        + "Below are excerpts taken from pages that were FETCHED AND READ IN "
        "FULL, each showing the text immediately around a mention of the target "
        "(not a search snippet). Extract ONLY facts the text states about THIS "
        "person — WHATEVER the page actually says about them. Do NOT assume "
        "they are any particular kind of person (student, professional, retiree, "
        "artist…); take the facts the text gives, whatever they are — roles, "
        "titles, affiliations, memberships, awards, positions, dates, places, "
        "relationships, activities. "
        "Rules: a fact must sit next to the target's own name; if an excerpt "
        "lists several people, attribute a fact to the target only when it is "
        "clearly theirs; never merge facts across unrelated lines; if nothing "
        "is clearly about the target, return an empty list.\n\n"
        f"{corpus}\n\n"
        'Respond ONLY as JSON: {"facts":["fact 1","fact 2"],"confidence":0.0}')
    datas = agent.fanout_json(
        "You extract grounded facts from full page text, never from guesses. "
        "Strict JSON only.", prompt, 800, label="read")

    facts: list = []
    low_seen: set = set()
    for d in (datas or []):
        for f in (d.get("facts") or []):
            f = str(f).strip()
            if f and f.lower() not in low_seen and len(f) <= 200:
                low_seen.add(f.lower())
                facts.append(f)
    if facts:
        _log(log, f"read: extracted {len(facts)} grounded fact(s) from "
                  f"{len(named_pages)} page(s)")
    return read, facts
