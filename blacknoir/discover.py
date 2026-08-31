"""Auto-discovery: find an obscure person's page by going to the SOURCE.

Google ranks by popularity, so an obscure person's one page (a school award
roster, a club member list) loses to their famous namesakes and never reaches
the top results a snippet API returns. A detective doesn't fight the ranking —
they go to the institution named in the context and read ITS pages.

This does that, free and automatically, by MERGING several free listings of a
domain's URLs — its sitemap, its homepage links, and the Wayback Machine's index
— because no single source is complete, but together they approach what a
'god-level' crawler sees. Discovered URLs are handed to deepread for reading.

Universal: it keys on whatever INSTITUTION the context names — school, company,
hospital, gallery, church — with no hardcoded target or category.
"""

from __future__ import annotations

import re
from typing import Callable, Optional
from urllib.parse import urlparse


def _log(cb: Optional[Callable[[str], None]], msg: str) -> None:
    if cb:
        cb(msg)


# Path words that mark a page likely to LIST an individual by name — awards,
# rosters, news, staff, members, obituaries. Deliberately broad and cross-domain
# (a gallery has 'exhibitions', a company has 'people', a school has 'awards').
_RELEVANT = ("award", "achiev", "prize", "honour", "honor", "student", "pupil",
             "result", "member", "roster", "news", "notice", "bulletin",
             "graduat", "alumni", "scholar", "champion", "winner", "people",
             "staff", "profile", "team", "exhibit", "obituar", "record",
             "activit", "club", "society", "event", "list")

# An institution phrase in the context: "... St. Brendon College ...".
_INSTITUTION = re.compile(
    r"([A-Za-z][\w.&'-]*(?:\s+[\w.&'-]+){0,6}?\s+"
    r"(?:School|College|University|Academy|Institute|Hospital|Church|Temple|"
    r"Gallery|Museum|Company|Ltd|Limited|Corp|Corporation|Department|"
    r"Association|Society|Club|Foundation|Centre|Center|Parish|Studio))",
    re.I)


_INST_FILLER = {"secondary", "primary", "student", "pupil", "at", "the", "a",
                "an", "of", "represented", "by", "engineer", "works", "worked",
                "employed", "in", "senior", "junior", "former", "retired",
                "current", "studied", "attends", "attended", "from", "teacher"}


def institution_name(context: str) -> str:
    """The institution phrase named in the context, or ''.

    Trims leading role/filler words so 'secondary student at St. Brendon
    College' yields 'St. Brendon College', not the whole clause.
    """
    m = _INSTITUTION.search(context or "")
    if not m:
        return ""
    words = m.group(1).split()
    while words and (words[0][:1].islower() or words[0].lower() in _INST_FILLER):
        words.pop(0)
    return " ".join(words).strip()


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def find_domain(inst: str, existing_urls: list, fetcher, log=None) -> str:
    """Official domain of the institution — from URLs already seen, else 1 search.

    An institution ranks #1 for its own name, so a single search resolves the
    domain with no namesake risk. We prefer a domain already present in the run's
    results (free) and only search if none matches.
    """
    if not inst:
        return ""
    toks = [t.lower() for t in re.findall(r"[A-Za-z]{3,}", inst)
            if t.lower() not in ("the", "and", "college", "school", "high",
                                 "university", "of", "hong", "kong")]
    # An initialism: 'St. Brendon College' -> 'sbc', which is exactly how a
    # school's domain (sbc.edu.example) is formed and which no substring test catches.
    inits = "".join(w[0] for w in inst.split() if w[:1].isalpha()).lower()

    def _core(h: str) -> str:
        parts = h.split(".")
        return parts[1] if parts[:1] == ["www"] and len(parts) >= 2 else parts[0]

    def _matches(h: str) -> bool:
        core = _core(h)
        if core and (core == inits or (len(inits) >= 2 and inits in core)):
            return True
        return any(t.startswith(core[:4]) or core.startswith(t[:4])
                   for t in toks if core)

    # 1. a domain already in the results whose host echoes the institution
    hosts: dict = {}
    for u in existing_urls or []:
        h = _host(u)
        if h and not any(h.endswith(n) for n in _NOISE_HOSTS):
            hosts[h] = hosts.get(h, 0) + 1
    for h in sorted(hosts, key=lambda x: -hosts[x]):
        if _matches(h):
            _log(log, f"institution domain (from results): {h}")
            return h
    # 2. one search for the institution name; take the first official-looking host
    try:
        from .config import get_source
        from .connectors import run_source
        src = get_source("serper")
        if src and src.available:
            run = run_source(src, inst, fetcher)
            for r in run.results:
                h = _host(getattr(r, "url", ""))
                if h and not any(h.endswith(n) for n in _NOISE_HOSTS):
                    _log(log, f"institution domain (searched): {h}")
                    return h
    except Exception as exc:
        _log(log, f"domain search failed: {type(exc).__name__}")
    return ""


# Hosts that are NEVER an institution's own website — search engines and social
# platforms, universally. Deliberately NOT a list of specific sites from any one
# case (an earlier draft hardcoded hosts seen in one target's results — that is
# exactly the per-target bias to avoid). These are generic infrastructure only.
_NOISE_HOSTS = ("google.", "bing.", "duckduckgo.", "facebook.", "linkedin.",
                "youtube.", "wikipedia.", "instagram.", "twitter.", "x.com",
                "baidu.", "reddit.", "pinterest.", "tiktok.")


def _get(url: str, fetcher) -> str:
    try:
        body = fetcher.get(url)
        return body or ""
    except Exception:
        return ""


def _sitemap_urls(domain: str, fetcher, log=None) -> list:
    """Every URL a domain lists in robots.txt sitemaps + /sitemap.xml."""
    found: list = []
    seen_maps: set = set()
    maps = [f"https://{domain}/sitemap.xml", f"https://{domain}/sitemap_index.xml"]
    robots = _get(f"https://{domain}/robots.txt", fetcher)
    for m in re.finditer(r"(?im)^\s*sitemap:\s*(\S+)", robots or ""):
        maps.append(m.group(1).strip())
    for mp in maps:
        if mp in seen_maps or len(seen_maps) > 8:
            continue
        seen_maps.add(mp)
        xml = _get(mp, fetcher)
        locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", xml or "", re.I)
        # a sitemap index points to more sitemaps
        for loc in locs:
            if loc.lower().endswith(".xml") and loc not in seen_maps:
                maps.append(loc)
            elif _host(loc) == domain or _host(loc).endswith("." + domain):
                found.append(loc)
    if found:
        _log(log, f"sitemap: {len(found)} URL(s) from {domain}")
    return found


def _home_links(domain: str, fetcher, log=None) -> list:
    """Same-domain links from the homepage (the site's own navigation)."""
    html = _get(f"https://{domain}/", fetcher)
    out: list = []
    for m in re.finditer(r'href=["\']([^"\']+)["\']', html or "", re.I):
        href = m.group(1)
        if href.startswith("/"):
            href = f"https://{domain}{href}"
        if _host(href) == domain or _host(href).endswith("." + domain):
            out.append(href.split("#")[0])
    out = list(dict.fromkeys(out))
    if out:
        _log(log, f"homepage: {len(out)} same-site link(s) on {domain}")
    return out


def _wayback_urls(domain: str, fetcher, log=None) -> list:
    """Every URL the Wayback Machine has archived for the domain (free CDX API)."""
    url = (f"http://web.archive.org/cdx/search/cdx?url={domain}/*"
           f"&output=json&fl=original&collapse=urlkey&limit=800")
    try:
        data = fetcher.get_json(url)
    except Exception:
        data = None
    rows = data if isinstance(data, list) else []
    out = [r[0] for r in rows[1:] if isinstance(r, list) and r]
    if out:
        _log(log, f"wayback: {len(out)} archived URL(s) for {domain}")
    return out


def _rank(urls: list, limit: int) -> list:
    """Prefer URLs whose PATH looks like it lists people (awards/news/members)."""
    scored = []
    for u in dict.fromkeys(urls):
        path = urlparse(u).path.lower()
        if not path or path in ("/", ""):
            continue
        score = sum(1 for w in _RELEVANT if w in path)
        # shallow, clean paths beat deep query-string junk
        depth_penalty = path.count("/") * 0.1 + (0.5 if "?" in u else 0)
        scored.append((score - depth_penalty, u))
    scored.sort(key=lambda x: -x[0])
    return [u for s, u in scored if s > 0][:limit]


def _llm_institution(context: str, agent, log=None) -> str:
    """Let the model name the institution — adapts to any org type/phrasing."""
    if not (agent and getattr(agent, "enabled", False)) or not context:
        return ""
    prompt = (
        f'CONTEXT: "{context}"\n'
        "Name the single institution / organisation / place in this context "
        "whose OWN website would plausibly list this person — a school, "
        "company, gallery, church, club, hospital, team, society, anything. "
        "Return just its name, or empty if the context names none.\n"
        'Respond ONLY as JSON: {"institution":"..."}')
    for d in (agent.fanout_json("You identify an institution. Strict JSON only.",
                                prompt, 120, label="institution") or []):
        v = str(d.get("institution") or "").strip()
        if v and len(v) <= 80:
            return v
    return ""


def _llm_pick(urls: list, target: str, context: str, agent, limit: int,
              log=None) -> list:
    """Let the model choose which discovered URLs to read — adapts to anyone.

    Beats a fixed keyword rank: the model judges each URL against WHO the target
    is (a pupil -> awards/roster; a retiree -> news/obituary; an artist ->
    exhibitions) rather than one hardcoded set of path words.
    """
    if not urls:
        return []
    sample = urls[:200]
    listing = "\n".join(f"{i}: {u}" for i, u in enumerate(sample))
    prompt = (
        f'TARGET: "{target}"\n' + (f'CONTEXT: "{context}"\n' if context else "")
        + "These URLs are all from one institution's own website. Pick the ones "
        "most likely to be a page that LISTS INDIVIDUALS BY NAME where this "
        "particular target could appear — reason from who they are and from the "
        "URL path. Do not assume a category; a pupil appears on award/roster "
        "pages, a retiree in news/obituaries, an artist in exhibitions, a "
        f"member on club pages. Return at most {limit} indices.\n\n{listing}\n\n"
        'Respond ONLY as JSON: {"pick":[0,3,7]}')
    idxs: list = []
    for d in (agent.fanout_json("You select URLs worth reading. Strict JSON.",
                                prompt, 400, label="pick") or []):
        for i in (d.get("pick") or []):
            if isinstance(i, int) and 0 <= i < len(sample):
                idxs.append(i)
    picked = [sample[i] for i in dict.fromkeys(idxs)][:limit]
    if picked:
        _log(log, f"discover: model picked {len(picked)} URL(s) to read "
                  f"(adaptive, not keyword-ranked)")
    return picked


def discover_urls(context: str, target: str, existing_urls: list, fetcher,
                  agent=None, log=None, limit: int = 12) -> tuple:
    """Merge free URL sources for the institution in the context.

    Returns (domain, urls). URLs are the pages most likely to name an individual
    — chosen by the model when available (adaptive to any persona), or by a
    generic keyword rank as a no-LLM fallback — handed to deepread to read.
    """
    inst = _llm_institution(context, agent, log) or institution_name(context)
    if not inst:
        _log(log, "discover: no institution named in the context — skipping")
        return "", []
    _log(log, f"discover: institution = '{inst}'")
    domain = find_domain(inst, existing_urls, fetcher, log)
    if not domain:
        _log(log, "discover: could not resolve an institution domain")
        return "", []
    merged: list = []
    merged += _sitemap_urls(domain, fetcher, log)
    merged += _home_links(domain, fetcher, log)
    merged += _wayback_urls(domain, fetcher, log)
    merged = list(dict.fromkeys(merged))
    # Adaptive first, keyword-rank only as the no-model fallback.
    chosen = _llm_pick(merged, target, context, agent, limit, log)
    if not chosen:
        chosen = _rank(merged, limit)
    _log(log, f"discover: merged {len(merged)} URL(s) from 3 free sources "
              f"-> {len(chosen)} to read")
    return domain, chosen
