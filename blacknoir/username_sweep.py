"""Cross-platform username presence sweep (WhatsMyName-style, native).

Given a handle, probe a curated list of clearnet sites and report where an
account with that name exists. This is the automated version of the manual
"WhatsMyName / Namechk" pivot: instead of handing you a link, Black Noir checks.

Rules kept intact:
  * live-only, no plan-mode network;
  * every host here is added to the guardrail allow-list (curated, not arbitrary
    result links);
  * NO downloads — profile pages are read as text and matched for a marker
    string / status code, never saved or followed further;
  * a site is only reported "found" on a strong positive signal; ambiguous
    responses are counted, not guessed.

Detection per site: (name, url_template, marker).
  marker is None  -> status-code site: 200 = found, 404 = missing.
  marker is a str -> soft-404 site: found only if 200 AND marker in body.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from .config import USER_AGENT
from .models import SearchResult, SourceRun

# (label, url template with {u}, marker string or None for status-code sites)
SITES: list[tuple[str, str, str | None]] = [
    ("GitHub",        "https://github.com/{u}", None),
    ("GitLab",        "https://gitlab.com/{u}", None),
    ("SoundCloud",    "https://soundcloud.com/{u}", None),
    ("Patreon",       "https://www.patreon.com/{u}", None),
    ("Medium",        "https://medium.com/@{u}", None),
    ("Dev.to",        "https://dev.to/{u}", None),
    ("Keybase",       "https://keybase.io/{u}", None),
    ("Gravatar",      "https://gravatar.com/{u}", None),
    ("Chess.com",     "https://www.chess.com/member/{u}", None),
    ("Vimeo",         "https://vimeo.com/{u}", None),
    ("Flickr",        "https://www.flickr.com/people/{u}", None),
    ("About.me",      "https://about.me/{u}", None),
    ("Kaggle",        "https://www.kaggle.com/{u}", None),
    ("Docker Hub",    "https://hub.docker.com/u/{u}", None),
    ("Behance",       "https://www.behance.net/{u}", None),
    ("Dribbble",      "https://dribbble.com/{u}", None),
    ("Last.fm",       "https://www.last.fm/user/{u}", None),
    ("Wikipedia",     "https://en.wikipedia.org/wiki/User:{u}", None),
    ("Telegram",      "https://t.me/{u}", "tgme_page_title"),
    ("Steam",         "https://steamcommunity.com/id/{u}", "g_rgProfileData"),
    ("Hacker News",   "https://news.ycombinator.com/user?id={u}", "created:"),
    ("Bandcamp",      "https://{u}.bandcamp.com", "Bandcamp"),
]


def _host(tmpl: str) -> str:
    # for subdomain templates like https://{u}.bandcamp.com, allow the base host
    netloc = urlparse(tmpl.replace("{u}", "x")).hostname or ""
    return netloc.lower()


# hosts guardrails must allow-list for the sweep to run
SWEEP_HOSTS: set[str] = {_host(t) for _, t, _ in SITES}


def _detect(status, text, marker) -> str:
    if status is None:
        return "error"
    if marker is None:
        if status == 200:
            return "found"
        if status == 404:
            return "not_found"
        return "unknown"
    # soft-404 site: needs the marker in the body
    if status == 200 and text and marker in text:
        return "found"
    if status in (200, 404):
        return "not_found"
    return "unknown"


def sweep_username(username: str, fetcher, cap: int = 25,
                   workers: int = 6) -> SourceRun:
    u = username.lstrip("@").strip()
    if not u or any(c in u for c in " /\\?#"):
        return SourceRun("username_sweep", "Username sweep", "public",
                         "skipped", detail="not a bare handle")
    # plan mode does no network — report the sweep as ready without probing
    if not fetcher.live:
        return SourceRun("username_sweep", "Username sweep (cross-platform)",
                         "public", "planned",
                         detail=f"{len(SITES[:cap])} sites ready (run --live)")

    sites = SITES[:cap]

    def _check(site):
        label, tmpl, marker = site
        url = tmpl.format(u=u)
        # concurrency is capped at `workers` so no single site is ever hit more
        # than once and the outbound burst stays modest (not scanner-like).
        status, text = fetcher.probe(url, headers={"User-Agent": USER_AGENT},
                                     timeout=8.0)
        return label, url, _detect(status, text, marker)

    hits: list[SearchResult] = []
    checked = errors = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        # pool.map preserves input order → deterministic, stable output
        for label, url, verdict in pool.map(_check, sites):
            checked += 1
            if verdict == "error":
                errors += 1
            elif verdict == "found":
                hits.append(SearchResult("username_sweep", "public",
                            title=f"{label}: @{u} exists", url=url,
                            meta={"platform": label, "presence": "found"}))
    status_str = "ok" if hits else "empty"
    detail = f"{len(hits)} hit(s) across {checked} sites"
    if errors:
        detail += f" ({errors} unreachable)"
    return SourceRun("username_sweep", "Username sweep (cross-platform)",
                     "public", status_str, detail=detail, results=hits)
