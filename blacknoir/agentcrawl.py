"""Agentic crawl: start at a URL and NAVIGATE a site toward the target.

Unlike a static sitemap dump, this READS a page, reasons about which links lead
toward pages that name the target, follows them, reads those, and repeats — a
bounded plan -> read -> decide -> step loop. The shape is Mr Red's operator
(a capped agent loop that observes and picks its next action), but this is
strictly READ-ONLY: the only action is 'fetch and read a public page'. It never
submits forms, runs code, or acts on the site — it navigates and reads, the way
a person clicking through a website would.

Universal & adaptive: the model reasons about ANY site's structure and about who
the target is. No hardcoded paths, domains, or personas — a keyword heuristic is
only the no-LLM fallback.
"""

from __future__ import annotations

import re
from typing import Callable, Optional
from urllib.parse import urljoin, urlparse


def _log(cb: Optional[Callable[[str], None]], msg: str) -> None:
    if cb:
        cb(msg)


def _same_site(u: str, root: str) -> bool:
    h = (urlparse(u).hostname or "").lower()
    r = (urlparse(root).hostname or "").lower()
    if not h or not r:
        return False
    return h == r or h.endswith("." + r) or r.endswith("." + h)


def _links(html: str, base: str, root: str) -> list:
    out: list = []
    for m in re.finditer(r'href=["\']([^"\'#]+)["\']', html or "", re.I):
        try:
            u = urljoin(base, m.group(1)).split("#")[0]
        except Exception:
            continue
        if u.startswith("http") and _same_site(u, root):
            out.append(u)
    return list(dict.fromkeys(out))


# no-LLM fallback only: path words that tend to lead to person listings
_LEADS = ("award", "achiev", "prize", "honour", "honor", "student", "pupil",
          "result", "member", "roster", "news", "notice", "graduat", "alumni",
          "scholar", "champion", "winner", "people", "staff", "team", "exhibit",
          "obituar", "event", "activit", "club", "list", "profile")


def _decide_next(current: str, target: str, context: str, snippet: str,
                 links: list, agent, log=None) -> list:
    """The 'think' step: which links lead toward a page that names the target."""
    if not (agent and getattr(agent, "enabled", False)) or not links:
        return [u for u in links
                if any(w in u.lower() for w in _LEADS)][:5]
    listing = "\n".join(f"{i}: {u}" for i, u in enumerate(links[:60]))
    prompt = (
        f'GOAL: find pages on THIS website that NAME "{target}"'
        + (f' (who: {context})' if context else "") + ".\n"
        f"You are currently on: {current}\n"
        f"Start of this page's text: {snippet[:600]}\n\n"
        f"Links found on this page (same site):\n{listing}\n\n"
        "Reason about the site's structure and where a person like the target "
        "would be named — award/roster/news/member/student/profile pages, a "
        "sitemap, a year/archive index. Pick the links most worth following "
        "next toward such a page. Do NOT assume a category; judge from the goal "
        "and the paths. Return at most 5 indices, best first.\n"
        'Respond ONLY as JSON: {"go":[0,3]}')
    idxs: list = []
    for d in (agent.fanout_json(
            "You navigate a website toward a named person, read-only. "
            "Strict JSON only.", prompt, 300, label="navigate") or []):
        for i in (d.get("go") or []):
            if isinstance(i, int) and 0 <= i < len(links):
                idxs.append(i)
    return [links[i] for i in dict.fromkeys(idxs)][:5]


def agent_crawl(start: str, target: str, aliases: list, context: str, fetcher,
                agent, log=None, max_steps: int = 12,
                max_named: int = 10) -> tuple:
    """Navigate from `start`, following links the agent judges promising.

    Returns (named_pages, visited). named_pages are pages whose text actually
    contains the target's name (ready for deepread to extract facts from).
    Bounded by max_steps (like Mr Red's agent_max_steps) so it always ends.
    """
    from .webfetch import fetch_page
    from .deepread import _windows

    names = [target] + [a for a in (aliases or []) if a]
    frontier: list = [start]
    visited: set = set()
    named_pages: list = []
    steps = 0
    _log(log, f"agent-crawl: start at {start} (max {max_steps} steps, read-only)")
    while frontier and steps < max_steps and len(named_pages) < max_named:
        url = frontier.pop(0)
        if url in visited:
            continue
        visited.add(url)
        steps += 1
        page = fetch_page(url, fetcher)
        text = page.get("text", "") if page.get("ok") else ""
        raw = ""
        try:
            raw = fetcher.get(url) or ""
        except Exception:
            raw = ""
        wins = _windows(text, names) if text else []
        if wins:
            named_pages.append({"url": url, "title": page.get("title") or "",
                                "named": True,
                                "excerpt": " … ".join(wins)[:1800]})
            _log(log, f"  step {steps}: \033[92mNAMES target\033[0m {url[:64]}")
        else:
            _log(log, f"  step {steps}: read {url[:64]}")
        links = [l for l in _links(raw, url, url)
                 if l not in visited and l not in frontier]
        for nxt in _decide_next(url, target, context, text, links, agent, log):
            if nxt not in visited and nxt not in frontier:
                frontier.insert(0, nxt)   # depth-first toward promising links
    _log(log, f"agent-crawl: {steps} page(s) visited, "
              f"{len(named_pages)} name the target")
    return named_pages, list(visited)
