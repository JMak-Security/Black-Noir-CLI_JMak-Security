"""Connector layer: one adapter per search source.

All connectors share `run_source`, which dispatches on the registry entry's
`kind` and always returns a `SourceRun` (never raises). Connectors only read
search-index result pages; they never follow the links those pages contain.
"""

from __future__ import annotations

import base64
import html as _html
import os
import re
import shlex
import shutil
import subprocess
import time
from urllib.parse import parse_qs, quote_plus, urlparse

from ..config import MAX_RESULTS_PER_SOURCE, USER_AGENT, Source
from ..guardrails import is_onion
from ..http import Fetcher
from ..models import SearchResult, SourceRun

try:
    from bs4 import BeautifulSoup  # type: ignore
    _HAS_BS4 = True
except Exception:
    BeautifulSoup = None  # type: ignore
    _HAS_BS4 = False


def _clean(text: str) -> str:
    return re.sub(r"\s+", " ", _html.unescape(text or "")).strip()


_BLOCK_MARKERS = ("challenge", "anomaly", "captcha", "unusual traffic",
                  "are you a robot", "verify you are human", "cf-browser-verification")


def _looks_blocked(body: str) -> bool:
    low = body[:6000].lower()
    return any(m in low for m in _BLOCK_MARKERS)


def _query_url(src: Source, query: str) -> str | None:
    if not src.query_url:
        return None
    return src.query_url.replace("{q}", quote_plus(query))


# --- HTML parsing helpers ---------------------------------------------------

def _parse_generic(html_text: str, source: Source) -> list[SearchResult]:
    """Best-effort extraction of <a> result links + nearby text.

    Deliberately generic so it survives minor markup drift across the many
    aggregator frontends. Onion links are captured as text, never fetched.
    """
    results: list[SearchResult] = []
    if not html_text:
        return results

    if _HAS_BS4:
        soup = BeautifulSoup(html_text, "html.parser")
        anchors = soup.find_all("a", href=True)
        for a in anchors:
            href = a["href"].strip()
            title = _clean(a.get_text())
            if not title or len(title) < 3:
                continue
            if not (href.startswith("http") or ".onion" in href):
                continue
            snippet = ""
            parent = a.find_parent(["li", "div", "article", "p"])
            if parent:
                snippet = _clean(parent.get_text())[:300]
            results.append(SearchResult(
                source=source.key, surface=source.surface,
                title=title[:200], url=href, snippet=snippet,
                is_onion=is_onion(href),
            ))
            if len(results) >= MAX_RESULTS_PER_SOURCE:
                break
    else:
        # regex fallback when bs4 is absent
        for m in re.finditer(r'<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
                             html_text, re.I | re.S):
            href, inner = m.group(1), _clean(re.sub("<[^>]+>", " ", m.group(2)))
            if not inner or not (href.startswith("http") or ".onion" in href):
                continue
            results.append(SearchResult(
                source=source.key, surface=source.surface,
                title=inner[:200], url=href, is_onion=is_onion(href),
            ))
            if len(results) >= MAX_RESULTS_PER_SOURCE:
                break

    # drop navigation/self links pointing back at the engine itself
    engine_host = source.clearnet.split("//")[-1]
    return [r for r in results if engine_host not in r.url][:MAX_RESULTS_PER_SOURCE]


def _parse_ddg(html_text: str, source: Source) -> list[SearchResult]:
    if not _HAS_BS4:
        return _parse_generic(html_text, source)
    soup = BeautifulSoup(html_text, "html.parser")
    out: list[SearchResult] = []
    for res in soup.select(".result, .web-result"):
        a = res.select_one(".result__a") or res.select_one("a.result__url")
        if not a:
            continue
        snip = res.select_one(".result__snippet")
        url_el = res.select_one(".result__url")
        url = _clean(url_el.get_text()) if url_el else a.get("href", "")
        if url and not url.startswith("http"):
            url = "https://" + url
        out.append(SearchResult(
            source=source.key, surface=source.surface,
            title=_clean(a.get_text())[:200], url=url,
            snippet=_clean(snip.get_text())[:300] if snip else "",
            is_onion=is_onion(url)))
        if len(out) >= MAX_RESULTS_PER_SOURCE:
            break
    return out


def _unwrap_bing_url(url: str) -> str:
    """Turn a bing.com/ck/a redirect into the destination it points at.

    Every organic Bing result is wrapped in a click-tracking redirect whose
    `u` parameter is the real URL, base64url-encoded behind an 'a1' prefix.
    Left wrapped, the entity graph would ingest 'bing.com' as the domain of
    every finding instead of github.com / linkedin.com — turning real pivots
    into tracking noise. Nothing is fetched here; this is pure decoding.
    """
    try:
        parsed = urlparse(url)
        if "bing.com" not in (parsed.hostname or "") or "/ck/a" not in parsed.path:
            return url
        u = (parse_qs(parsed.query).get("u") or [""])[0]
        if not u.startswith("a1"):
            return url
        raw = u[2:]
        raw += "=" * (-len(raw) % 4)
        out = base64.urlsafe_b64decode(raw).decode("utf-8", "replace")
        return out if out.startswith("http") else url
    except Exception:
        return url


def _parse_bing_rss(body: str, source: Source) -> list[SearchResult]:
    """Parse Bing's RSS SERP (`&format=rss`).

    Preferred over scraping the HTML page: the feed carries real destination
    URLs (no bing.com/ck/a click-wrappers), needs no bs4, is immune to markup
    drift, and honours the query noticeably more often than the HTML endpoint.
    """
    out: list[SearchResult] = []
    if not body:
        return out
    for chunk in re.findall(r"<item>(.*?)</item>", body, re.S | re.I):
        t = re.search(r"<title>(.*?)</title>", chunk, re.S | re.I)
        l = re.search(r"<link>(.*?)</link>", chunk, re.S | re.I)
        d = re.search(r"<description>(.*?)</description>", chunk, re.S | re.I)
        url = _clean(_html.unescape(l.group(1))) if l else ""
        title = _clean(_html.unescape(re.sub("<[^>]+>", " ", t.group(1)))) if t else ""
        if not url.startswith("http") or not title:
            continue
        snippet = (_clean(_html.unescape(re.sub("<[^>]+>", " ", d.group(1))))
                   if d else "")
        out.append(SearchResult(
            source=source.key, surface=source.surface,
            title=title[:200], url=url, snippet=snippet[:300],
            is_onion=is_onion(url)))
        if len(out) >= MAX_RESULTS_PER_SOURCE:
            break
    return out


# Query words too generic to prove a result set is on-topic.
_DECOY_STOPWORDS = {"the", "and", "for", "with", "from", "site", "www", "com",
                    "http", "https", "org", "net", "search", "your", "how"}


def _query_terms(query: str) -> list[str]:
    """Distinctive terms from a query, for checking a result set against it."""
    raw = re.split(r"[\s\"'()]+", (query or "").lower())
    terms = []
    for t in raw:
        t = t.strip(".,:;!?").replace("site:", "")
        if not t or t in _DECOY_STOPWORDS:
            continue
        # CJK has no spaces, so a short run of CJK is still a real term
        if len(t) >= 3 or any("㐀" <= c <= "鿿" for c in t):
            terms.append(t)
    return terms


def _looks_like_decoy(results: list[SearchResult], query: str) -> bool:
    """True when a result set shares NO term with the query it answered.

    Bing serves randomised decoy SERPs to unauthenticated clients: measured
    over repeated identical requests it returns a different unrelated page set
    each time (protein bars, then a piracy site, then a login page) rather than
    an error. Those pages are well-formed, so nothing downstream can tell them
    from real findings — they simply arrive as noise attached to the target's
    name. A genuine result set echoes at least one query term somewhere across
    ten results; a decoy set echoes none.
    """
    terms = _query_terms(query)
    if not terms or not results:
        return False
    blob = " ".join(f"{r.title} {r.url} {r.snippet}" for r in results).lower()
    return not any(t in blob for t in terms)


# Phrases an engine uses when it genuinely has nothing. Their presence proves
# the page IS a result page we read correctly — it just holds zero results.
_NO_RESULT_MARKERS = (
    "did not match any", "no results", "no result found", "0 results",
    "nothing found", "try different keywords", "check your spelling",
    "aucun résultat", "keine ergebnisse", "沒有找到", "没有找到",
)

# Below this, a body is too small to be a populated SERP and too likely to be
# an error/interstitial for the zero-result reading to be suspicious.
_PARSER_BREAK_MIN_BODY = 2000
# A real SERP is dense with links. If the page has this many and our dedicated
# parser still found nothing, the selector — not the target — is the problem.
_PARSER_BREAK_MIN_ANCHORS = 20


def _looks_like_parser_break(body: str, source: Source,
                             results: list) -> bool:
    """True when a 200 response probably means OUR selector went stale.

    A dedicated parser anchors on markup (`li.b_algo`, `.result__a`, `<item>`).
    When an engine redesigns, those selectors match nothing and the connector
    reports `empty` — indistinguishable, downstream, from "this person has no
    footprint". That is the single worst failure mode this tool has: a silent
    false negative caused by a bug on OUR side, reported as a fact about the
    target.

    A genuinely empty SERP is short and/or says so in words. A populated page
    our parser cannot read is long and link-dense. That is the difference this
    checks, and it only applies to sources with a dedicated parser — the
    generic anchor scraper has no selector to go stale.
    """
    if results or source.key not in _PARSERS or not body:
        return False
    if len(body) < _PARSER_BREAK_MIN_BODY:
        return False
    low = body[:20000].lower()
    if any(m in low for m in _NO_RESULT_MARKERS):
        return False  # the engine told us it found nothing; believe it
    # RSS feeds carry <item>, HTML pages carry <a href>. Either counts as
    # "the payload is here and we failed to read it".
    anchors = len(re.findall(r"<a\s[^>]*href=", body, re.I))
    items = len(re.findall(r"<item[\s>]", body, re.I))
    return anchors >= _PARSER_BREAK_MIN_ANCHORS or items >= 3


def _parse_bing(html_text: str, source: Source) -> list[SearchResult]:
    """Extract Bing's organic results (`<li class="b_algo">`).

    Bing was previously read with the generic anchor scraper, which walks every
    <a> on the page — including the stylesheet/nav/related-search furniture that
    surrounds each result. That is what produced the off-query noise ("Alex
    Voorhees" for an unrelated name) that got Bing removed: the engine WAS
    honouring the query, but the parser was not reading the answer. Anchoring on
    the result container and taking only its heading link fixes it at the source.
    """
    if not _HAS_BS4:
        return _parse_generic(html_text, source)
    soup = BeautifulSoup(html_text, "html.parser")
    out: list[SearchResult] = []
    for res in soup.select("li.b_algo"):
        h = res.select_one("h2 a[href]") or res.select_one("a[href]")
        if not h:
            continue
        url = _unwrap_bing_url((h.get("href") or "").strip())
        if not url.startswith("http"):
            continue
        title = _clean(h.get_text())
        if not title:
            continue
        snip = (res.select_one(".b_caption p") or res.select_one("p")
                or res.select_one(".b_snippet"))
        out.append(SearchResult(
            source=source.key, surface=source.surface,
            title=title[:200], url=url,
            snippet=_clean(snip.get_text())[:300] if snip else "",
            is_onion=is_onion(url)))
        if len(out) >= MAX_RESULTS_PER_SOURCE:
            break
    return out


_PARSERS = {"duckduckgo": _parse_ddg, "bing": _parse_bing_rss}

# Sources whose results must be checked against the query before use. Only
# engines observed serving decoy SERPs belong here — the check costs nothing
# but silently dropping a real result set would be worse than the noise.
_DECOY_PRONE = {"bing"}


# --- breach connectors ------------------------------------------------------

_DOMAINISH = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)


def _run_breach(src: Source, query: str, fetcher: Fetcher) -> SourceRun:
    if src.key == "hibp":
        return _run_hibp(query, fetcher)
    if src.key == "xposed":
        return _run_xposed(query, fetcher)
    return _run_dehashed(query, fetcher)


def _hibp_breaches_by_domain(domain: str, fetcher: Fetcher, note: str) -> SourceRun:
    """KEYLESS: real breaches that affected a domain/company (HIBP public API)."""
    url = f"https://haveibeenpwned.com/api/v3/breaches?Domain={quote_plus(domain)}"
    data = fetcher.get_json(url, headers={"User-Agent": USER_AGENT})
    if data is None:
        status = "blocked" if fetcher.live else "planned"
        return SourceRun("hibp", "Have I Been Pwned", "darkweb", status,
                         detail=f"keyless HIBP domain lookup for {domain} "
                                "(no response / plan-only).")
    breaches = data if isinstance(data, list) else []
    results = [SearchResult(
        "hibp", "darkweb",
        title=f"Breach: {b.get('Name', '?')} ({b.get('BreachDate', '')})",
        url=f"https://haveibeenpwned.com/PwnedWebsites#{b.get('Name','')}",
        snippet=(f"{b.get('Title','')} — {b.get('PwnCount','?')} accounts; "
                 f"data: {', '.join(b.get('DataClasses', [])[:6])}")[:300],
        meta={"classes": b.get("DataClasses", []), "date": b.get("BreachDate")},
    ) for b in breaches[:MAX_RESULTS_PER_SOURCE]]
    return SourceRun("hibp", "Have I Been Pwned", "darkweb",
                     "ok" if results else "empty", detail=note, results=results)


def _run_hibp(query: str, fetcher: Fetcher) -> SourceRun:
    import os
    key = os.environ.get("HIBP_API_KEY", "")
    is_email = "@" in query
    domain = (query.split("@")[-1] if is_email
              else (query if _DOMAINISH.match(query.strip()) else None))

    # Domain/company target -> keyless breaches-by-domain (real data, no key).
    if domain and not is_email:
        return _hibp_breaches_by_domain(
            domain, fetcher, f"keyless domain breach lookup for {domain}.")

    # Account target with a key -> per-account exposure (the strong signal).
    if is_email and key:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote_plus(query)}?truncateResponse=false"
        data = fetcher.get_json(url, headers={"hibp-api-key": key,
                                              "User-Agent": USER_AGENT})
        if data is None:
            status = "blocked" if fetcher.live else "planned"
            return SourceRun("hibp", "Have I Been Pwned", "darkweb", status,
                             detail="per-account HIBP lookup (no response/plan-only).")
        if isinstance(data, dict) and data.get("__status__") == 404:
            return SourceRun("hibp", "Have I Been Pwned", "darkweb", "empty",
                             detail="no breaches for this account.")
        breaches = data if isinstance(data, list) else []
        results = [SearchResult(
            "hibp", "darkweb", title=f"Breach: {b.get('Name', '?')}",
            snippet=f"{b.get('Title','')} — {b.get('BreachDate','')}: "
                    f"{_clean(b.get('Description',''))[:200]}",
            meta={"classes": b.get("DataClasses", [])}) for b in breaches]
        return SourceRun("hibp", "Have I Been Pwned", "darkweb",
                         "ok" if results else "empty", results=results)

    # Account target, no key -> keyless is impossible per-account (by design),
    # but we can still show keyless breaches for the account's DOMAIN.
    if is_email and domain:
        run = _hibp_breaches_by_domain(
            domain, fetcher,
            f"keyless: breaches affecting domain '{domain}'. Per-account exposure "
            f"for {query} needs HIBP_API_KEY (HIBP blocks keyless email lookups).")
        return run
    return SourceRun("hibp", "Have I Been Pwned", "darkweb", "skipped",
                     detail="per-account lookup needs HIBP_API_KEY; keyless mode "
                            "works for domain/company targets.")


def _run_xposed(query: str, fetcher: Fetcher) -> SourceRun:
    """KEYLESS per-email breach lookup via XposedOrNot's free public API.

    The point of this source is the gap HIBP leaves: HIBP refuses keyless
    per-account (email) lookups, so without a paid HIBP_API_KEY an email target
    got no account-level breach signal at all. XposedOrNot indexes the same kind
    of dump data and answers keylessly, so "is this address in a known breach"
    — the single most useful free leak signal — is answerable again.

    Email-only by construction: the endpoint keys on an address. A non-email
    query (including the 'X leak' / 'X breach' variants the dark-web sweep
    generates) is a deliberate no-op so the ~100/day per-IP quota is spent only
    on the real address, not on junk that can never match.
    """
    label = "XposedOrNot (keyless breach)"
    q = (query or "").strip()
    if "@" not in q or " " in q or "." not in q.split("@")[-1]:
        return SourceRun("xposed", label, "darkweb", "empty",
                         detail="email-only source; query was not a bare "
                                "address, so nothing was requested.",
                         queries=[query])
    if not fetcher.live:
        return SourceRun("xposed", label, "darkweb", "planned",
                         detail=f"plan-only; would query XposedOrNot for {q}.",
                         queries=[query])
    url = (f"https://api.xposedornot.com/v1/breach-analytics"
           f"?email={quote_plus(q)}")
    data = fetcher.get_json(url, headers={"User-Agent": USER_AGENT})
    if data is None:
        return SourceRun("xposed", label, "darkweb", "blocked",
                         detail="no response (rate-limited or timed out); the "
                                "free tier allows ~25/hr, 100/day per IP.",
                         queries=[query])
    # A clean address comes back either as an error body or with no breach list.
    exposed = data.get("ExposedBreaches") if isinstance(data, dict) else None
    breaches = (exposed or {}).get("breaches_details") if isinstance(exposed, dict) else None
    if not breaches:
        return SourceRun("xposed", label, "darkweb", "empty",
                         detail=f"no breach record for {q} in XposedOrNot's "
                                "index (this address is not in a dump it knows).",
                         queries=[query])
    results: list[SearchResult] = []
    for b in breaches[:MAX_RESULTS_PER_SOURCE]:
        name = b.get("breach") or "?"
        classes = str(b.get("xposed_data") or "")
        recs = b.get("xposed_records")
        results.append(SearchResult(
            "xposed", "darkweb",
            title=f"Breach: {name} ({b.get('xposed_date', '')})",
            url="https://xposedornot.com/",
            snippet=(f"{_clean(str(b.get('details', '')))[:180]} — exposed: "
                     f"{classes.replace(';', ', ')}"
                     f"{f' ; ~{recs:,} records' if isinstance(recs, int) else ''}"
                     )[:300],
            meta={"classes": [c for c in classes.split(";") if c],
                  "records": recs, "domain": b.get("domain"),
                  "verified": b.get("verified")}))
    return SourceRun("xposed", label, "darkweb", "ok",
                     detail=f"{len(results)} breach(es) name {q} — free, keyless "
                            "(fills HIBP's keyless-email gap).",
                     results=results, queries=[query])


def _run_dehashed(query: str, fetcher: Fetcher) -> SourceRun:
    import os
    key = os.environ.get("DEHASHED_API_KEY", "")
    email = os.environ.get("DEHASHED_EMAIL", "")
    if not key:
        return SourceRun("dehashed", "DeHashed", "darkweb", "skipped",
                         detail="needs DEHASHED_API_KEY (+DEHASHED_EMAIL). DeHashed "
                                "has no keyless endpoint; use keyless HIBP (domains) "
                                "instead.")
    # DeHashed uses HTTP basic auth (email:api_key), not a bare key.
    import base64
    url = f"https://api.dehashed.com/search?query={quote_plus(query)}"
    auth = base64.b64encode(f"{email}:{key}".encode()).decode()
    data = fetcher.get_json(url, headers={"Accept": "application/json",
                                          "Authorization": f"Basic {auth}"})
    if data is None:
        status = "blocked" if fetcher.live else "planned"
        return SourceRun("dehashed", "DeHashed", "darkweb", status,
                         detail="DeHashed query (no response/plan-only).")
    entries = (data.get("entries") or []) if isinstance(data, dict) else []
    results = [SearchResult(
        "dehashed", "darkweb",
        title=f"Leaked record ({e.get('database_name', 'db')})",
        snippet=_clean(", ".join(f"{k}={v}" for k, v in e.items()
                       if k in ("email", "username", "name", "phone") and v))[:200],
    ) for e in entries[:MAX_RESULTS_PER_SOURCE]]
    return SourceRun("dehashed", "DeHashed", "darkweb",
                     "ok" if results else "empty", results=results)


# --- Serper (Google SERP API) ----------------------------------------------

def _serper_call(key: str, query: str, fetcher: Fetcher):
    return fetcher.post(
        "https://google.serper.dev/search",
        json_body={"q": query, "num": 20},
        headers={"X-API-KEY": key, "Content-Type": "application/json"},
        as_json=True)


def _run_serper(src: Source, query: str, fetcher: Fetcher) -> SourceRun:
    import os
    from ..config import sanitize_query, has_advanced_operators
    key = os.environ.get("SERPER_API_KEY", "")
    if not key:
        return SourceRun(src.key, src.label, src.surface, "skipped",
                         detail="needs SERPER_API_KEY", queries=[query])

    # Some Serper plans reject phrase quotes and operators with HTTP 400
    # ("Query pattern not allowed for free accounts"); others accept them. Ask
    # as precisely as the query was written, and fall back to plain keywords
    # only when the API actually refuses the syntax — so a plan that supports
    # operators keeps their precision, and one that does not still returns
    # results instead of dying on its first query.
    attempts = [query]
    if has_advanced_operators(query):
        plain = sanitize_query(query)
        if plain and plain != query:
            attempts.append(plain)      # fallback, tried only on a 400

    data, used, note = None, query, ""
    for i, q in enumerate(attempts):
        data = _serper_call(key, q, fetcher)
        used = q
        if data is not None:
            if i > 0:
                note = (f"this Serper plan rejects search operators; retried "
                        f"as plain keywords ({q!r}). ")
            break
        err = fetcher.last_error or (None, "")
        if err[0] == 400 and "not allowed" in (err[1] or "").lower():
            continue                    # try the sanitized fallback
        break                           # any other failure: retrying won't help

    if data is None:
        if fetcher.live:
            code, body = (fetcher.last_error or (None, ""))
            why = f"HTTP {code}: {body[:160]}" if code else (body[:160] or
                                                             "no response")
            return SourceRun(src.key, src.label, src.surface, "blocked",
                             detail=f"Serper failed — {why}", queries=attempts)
        return SourceRun(src.key, src.label, src.surface, "planned",
                         detail="plan-only; would query Serper.", queries=[query])
    query = used
    results: list[SearchResult] = []
    ab = data.get("answerBox") or {}
    if ab.get("answer") or ab.get("snippet"):
        results.append(SearchResult(
            src.key, src.surface, title=f"[answer] {ab.get('title','')}"[:200],
            url=ab.get("link", ""), snippet=_clean(ab.get("answer") or ab.get("snippet"))[:300]))
    kg = data.get("knowledgeGraph") or {}
    if kg.get("title"):
        attrs = "; ".join(f"{k}={v}" for k, v in (kg.get("attributes") or {}).items())
        results.append(SearchResult(
            src.key, src.surface, title=f"[knowledge] {kg.get('title')}"[:200],
            url=kg.get("website") or kg.get("descriptionLink", ""),
            snippet=_clean(f"{kg.get('type','')} {kg.get('description','')} {attrs}")[:300]))
    for o in (data.get("organic") or []):
        results.append(SearchResult(
            src.key, src.surface, title=_clean(o.get("title", ""))[:200],
            url=o.get("link", ""), snippet=_clean(o.get("snippet", ""))[:300],
            is_onion=is_onion(o.get("link", "")),
            meta={"position": o.get("position")}))
    return SourceRun(src.key, src.label, src.surface,
                     "ok" if results else "empty", detail=note,
                     results=results[:MAX_RESULTS_PER_SOURCE], queries=[query])


# --- Intelligence X (deep/dark-web index via clearnet API) ------------------
# IntelX indexes leaks, pastes, darknet (Tor/I2P), whois, dumpster and more,
# and exposes it through a clearnet JSON API with an API key. It is the closest
# thing to reaching onion/leak content *without* Tor. Two hard rules keep it
# aligned with Black Noir's guardrails:
#   1. We call /intelligent/search and read RECORD METADATA only (name, bucket,
#      date, type). We never call /file/read or /file/view — pulling the actual
#      leaked file bytes is the "possession" risk the whole tool avoids.
#   2. Search is credit-metered (free tier: ~50 searches), so IntelX runs ONCE
#      per investigation on the exact target, not per query variation.

def _run_intelx(src: Source, query: str, fetcher: Fetcher) -> SourceRun:
    # One or more keys, comma/whitespace separated. Extra keys are failover:
    # when the first is out of credits (HTTP 402/429) or errors, try the next.
    raw = os.environ.get("INTELX_API_KEY", "")
    keys = [k.strip() for k in raw.replace("\n", ",").replace(" ", ",").split(",")
            if k.strip()]
    if not keys:
        return SourceRun(src.key, src.label, src.surface, "skipped",
                         detail="needs INTELX_API_KEY", queries=[query])
    base = os.environ.get("INTELX_BASE", "https://free.intelx.io").rstrip("/")

    # 1. start the async search, failing over across keys
    start = None
    used_key = keys[0]
    used_idx = 0
    last_why = "no response"
    for idx, key in enumerate(keys):
        hdr = {"x-key": key, "User-Agent": USER_AGENT,
               "Content-Type": "application/json"}
        resp = fetcher.post(
            f"{base}/intelligent/search",
            json_body={"term": query, "buckets": [], "lookuplevel": 0,
                       "maxresults": MAX_RESULTS_PER_SOURCE, "timeout": 0,
                       "datefrom": "", "dateto": "", "sort": 4, "media": 0,
                       "terminate": []},
            headers=hdr, as_json=True)
        if isinstance(resp, dict) and resp.get("id"):
            start, used_key, used_idx = resp, key, idx
            break
        code, body = (fetcher.last_error or (None, ""))
        last_why = (f"HTTP {code}: {body[:120]}" if code
                    else (body[:120] or "no response"))
        if code in (402, 429) and idx + 1 < len(keys):
            continue  # out of credits — fail over to the backup key
        # any other error also falls through to the next key if one exists
    if start is None:
        if fetcher.live:
            hint = (" (all keys out of credits?)"
                    if "402" in last_why or "429" in last_why else "")
            return SourceRun(src.key, src.label, src.surface, "blocked",
                             detail=f"IntelX search failed on {len(keys)} key(s) "
                                    f"— {last_why}{hint}", queries=[query])
        return SourceRun(src.key, src.label, src.surface, "planned",
                         detail="plan-only; would query IntelX.", queries=[query])

    hdr = {"x-key": used_key, "User-Agent": USER_AGENT,
           "Content-Type": "application/json"}
    sid = start["id"]
    # 2. poll results (status: 0=results, 1=none yet, 2/3=done/expired)
    records: list = []
    for _ in range(6):
        data = fetcher.get_json(
            f"{base}/intelligent/search/result?id={sid}"
            f"&limit={MAX_RESULTS_PER_SOURCE}", headers=hdr)
        if not isinstance(data, dict):
            break
        records.extend(data.get("records") or [])
        if data.get("status") in (2, 3) or len(records) >= MAX_RESULTS_PER_SOURCE:
            break
        time.sleep(1)
    # free the concurrent-search slot (best-effort)
    fetcher.get_json(f"{base}/intelligent/search/terminate?id={sid}", headers=hdr)

    seen: set = set()
    results: list[SearchResult] = []
    for r in records:
        sysid = r.get("systemid") or r.get("storageid") or ""
        if sysid and sysid in seen:
            continue
        seen.add(sysid)
        name = _clean(r.get("name") or "(unnamed item)")
        bucket = r.get("bucket") or ""
        date = (r.get("date") or "")[:10]
        mtype = r.get("mediah") or r.get("typeh") or ""
        # clearnet reference to the item's IntelX view (metadata; not fetched)
        url = f"https://intelx.io/?did={sysid}" if sysid else ""
        results.append(SearchResult(
            src.key, src.surface, title=name[:200], url=url,
            snippet=_clean(f"{bucket} · {date} · {mtype}")[:300],
            is_onion=is_onion(name),
            meta={"bucket": bucket, "date": date, "systemid": sysid}))
        if len(results) >= MAX_RESULTS_PER_SOURCE:
            break
    keynote = f" [key #{used_idx + 1}/{len(keys)}]" if len(keys) > 1 else ""
    return SourceRun(src.key, src.label, src.surface,
                     "ok" if results else "empty",
                     detail=f"IntelX index (metadata only; file bytes not "
                            f"fetched){keynote}.",
                     results=results, queries=[query])


# --- keyless infra / reference sources --------------------------------------
# crt.sh + Wayback deliberately live in enrich.py (enrich_domain), not here —
# see the NOTE in config.py. These add signals enrichment does not cover.

_IPISH = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _domain_or_ip(query: str) -> str:
    term = (query or "").strip().lower()
    if "@" in term:
        term = term.split("@")[-1]
    return term


def _rdap_fn(ent: dict) -> str:
    """Pull the display name (vCard 'fn') from an RDAP entity."""
    v = ent.get("vcardArray")
    if isinstance(v, list) and len(v) > 1 and isinstance(v[1], list):
        for item in v[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                return str(item[3])
    return str(ent.get("handle", "") or "")


def _run_rdap(src: Source, query: str, fetcher: Fetcher) -> SourceRun:
    """Keyless WHOIS/registration data for a DOMAIN target."""
    term = _domain_or_ip(query)
    if not _DOMAINISH.match(term):
        return SourceRun(src.key, src.label, src.surface, "skipped",
                         detail="RDAP needs a domain target.", queries=[query])
    data = fetcher.get_json(f"https://rdap.org/domain/{quote_plus(term)}",
                            headers={"User-Agent": USER_AGENT})
    if not isinstance(data, dict):
        status = "blocked" if fetcher.live else "planned"
        return SourceRun(src.key, src.label, src.surface, status,
                         detail=f"RDAP lookup for {term} (no response/plan-only).",
                         queries=[query])
    if data.get("__status__") == 404 or "ldhName" not in data:
        return SourceRun(src.key, src.label, src.surface, "empty",
                         detail="RDAP: domain not found/registered.", queries=[query])
    results: list[SearchResult] = []
    for ent in data.get("entities", []) or []:
        if "registrar" in (ent.get("roles") or []):
            name = _rdap_fn(ent)
            if name:
                results.append(SearchResult(
                    src.key, src.surface, title=f"Registrar: {name}"[:200],
                    url="", snippet="domain registrar", meta={"role": "registrar"}))
    for ev in data.get("events", []) or []:
        action = ev.get("eventAction", "")
        date = (ev.get("eventDate", "") or "")[:10]
        if action and date:
            results.append(SearchResult(
                src.key, src.surface, title=f"{action}: {date}"[:200],
                url="", snippet="registration event", meta={"event": action}))
    for ns in data.get("nameservers", []) or []:
        n = str(ns.get("ldhName", "")).lower()
        if n:
            results.append(SearchResult(
                src.key, src.surface, title=f"NS: {n}"[:200], url="",
                snippet="nameserver", meta={"kind": "ns"}))
    return SourceRun(src.key, src.label, src.surface,
                     "ok" if results else "empty",
                     results=results[:MAX_RESULTS_PER_SOURCE], queries=[query])


def _run_hackertarget(src: Source, query: str, fetcher: Fetcher,
                      endpoint: str) -> SourceRun:
    """Shared driver for HackerTarget text APIs (reverse-IP, hostsearch)."""
    term = _domain_or_ip(query)
    if not (_DOMAINISH.match(term) or _IPISH.match(term)):
        return SourceRun(src.key, src.label, src.surface, "skipped",
                         detail="needs a domain/IP target.", queries=[query])
    text = fetcher.get(f"https://api.hackertarget.com/{endpoint}/?q="
                       f"{quote_plus(term)}")
    if text is None:
        status = "blocked" if fetcher.live else "planned"
        return SourceRun(src.key, src.label, src.surface, status,
                         detail=f"{src.label} for {term} (no response/plan-only).",
                         queries=[query])
    low = text.strip().lower()
    if "api count exceeded" in low:
        return SourceRun(src.key, src.label, src.surface, "blocked",
                         detail="HackerTarget free quota exceeded.", queries=[query])
    if low.startswith("error") or "no records" in low or "no dns" in low:
        return SourceRun(src.key, src.label, src.surface, "empty",
                         detail=text.strip()[:120], queries=[query])
    seen: set = set()
    results: list[SearchResult] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        host = line.split(",")[0].strip().lower()
        ip = line.split(",")[1].strip() if "," in line else ""
        if not host or host in seen:
            continue
        seen.add(host)
        results.append(SearchResult(
            src.key, src.surface, title=host[:200], url=f"https://{host}",
            snippet=(f"IP {ip}" if ip else "co-hosted domain"),
            is_onion=is_onion(host), meta={"ip": ip}))
        if len(results) >= MAX_RESULTS_PER_SOURCE:
            break
    return SourceRun(src.key, src.label, src.surface,
                     "ok" if results else "empty", results=results, queries=[query])


def _run_pdns(src: Source, query: str, fetcher: Fetcher) -> SourceRun:
    """Mnemonic passive DNS — historical resolutions (keyless)."""
    term = _domain_or_ip(query)
    if not (_DOMAINISH.match(term) or _IPISH.match(term)):
        return SourceRun(src.key, src.label, src.surface, "skipped",
                         detail="passive DNS needs a domain/IP target.",
                         queries=[query])
    data = fetcher.get_json(f"https://api.mnemonic.no/pdns/v3/{quote_plus(term)}",
                            headers={"User-Agent": USER_AGENT})
    if not isinstance(data, dict):
        status = "blocked" if fetcher.live else "planned"
        return SourceRun(src.key, src.label, src.surface, status,
                         detail=f"passive DNS for {term} (no response/plan-only).",
                         queries=[query])
    rows = data.get("data") or []
    seen: set = set()
    results: list[SearchResult] = []
    for e in rows:
        ans = str(e.get("answer", "")).strip()
        rrtype = str(e.get("rrtype", "")).upper()
        q = str(e.get("query", "")).strip()
        keyk = (q, rrtype, ans)
        if not ans or keyk in seen:
            continue
        seen.add(keyk)
        results.append(SearchResult(
            src.key, src.surface, title=f"{q} {rrtype} {ans}"[:200], url="",
            snippet=f"passive DNS {rrtype}", meta={"rrtype": rrtype, "answer": ans}))
        if len(results) >= MAX_RESULTS_PER_SOURCE:
            break
    return SourceRun(src.key, src.label, src.surface,
                     "ok" if results else "empty", results=results, queries=[query])


def _run_wikidata(src: Source, query: str, fetcher: Fetcher) -> SourceRun:
    """Wikidata entity search — structured facts for notable people/orgs."""
    term = (query or "").strip()
    if not term:
        return SourceRun(src.key, src.label, src.surface, "empty", queries=[query])
    url = ("https://www.wikidata.org/w/api.php?action=wbsearchentities"
           f"&search={quote_plus(term)}&language=en&format=json"
           f"&limit={MAX_RESULTS_PER_SOURCE}")
    data = fetcher.get_json(url, headers={"User-Agent": USER_AGENT})
    if not isinstance(data, dict):
        status = "blocked" if fetcher.live else "planned"
        return SourceRun(src.key, src.label, src.surface, status,
                         detail=f"Wikidata search for {term} (no response/plan-only).",
                         queries=[query])
    hits = data.get("search") or []
    results: list[SearchResult] = []
    for h in hits:
        qid = h.get("id", "")
        label = h.get("label", "")
        desc = h.get("description", "")
        results.append(SearchResult(
            src.key, src.surface, title=f"{label} ({qid})"[:200],
            url=h.get("concepturi") or f"https://www.wikidata.org/wiki/{qid}",
            snippet=_clean(desc)[:300], meta={"qid": qid}))
        if len(results) >= MAX_RESULTS_PER_SOURCE:
            break
    return SourceRun(src.key, src.label, src.surface,
                     "ok" if results else "empty", results=results, queries=[query])


# --- GitHub code search -----------------------------------------------------

def _is_code_identifier(query: str) -> bool:
    """Is this query something that can appear verbatim in source code?

    Code search matches file contents, so it keys on identifiers — a handle, an
    email, a domain, an API token. A bare multi-word phrase is not one, and
    searching it returns documents that merely contain the words somewhere:
    "Lam Wing Kit" matched a dozen NEWS changelogs (`lam`, `wing`, `kit` all occur
    in release notes), none of which concerned any person. That noise is worse
    than useless downstream, because the repo owners it surfaces then become
    handle-confirmation candidates.

    Single tokens and anything carrying identifier punctuation (`@ . _ -`, or a
    digit/letter mix) still qualify; only the bare word-phrase is declined.
    """
    q = (query or "").strip()
    if not q:
        return False
    if any(ch in q for ch in "@._-/:"):
        return True
    return len(q.split()) == 1


def _run_github(src: Source, query: str, fetcher: Fetcher) -> SourceRun:
    """GitHub code search — leaked secrets / handle-to-identity. Needs a (free)
    personal access token; code search is auth-only on the GitHub API."""
    if not _is_code_identifier(query):
        return SourceRun(
            src.key, src.label, src.surface, "skipped",
            detail=("code search keys on identifiers that appear in source "
                    "files (handle, email, domain, token). A multi-word phrase "
                    "matches documents containing the words separately, not the "
                    "subject — declined rather than queried. Pivot to a handle "
                    "or email to use this source."),
            queries=[query])
    key = os.environ.get("GITHUB_TOKEN", "")
    if not key:
        return SourceRun(src.key, src.label, src.surface, "skipped",
                         detail="needs GITHUB_TOKEN (free personal access token)",
                         queries=[query])
    hdr = {"Authorization": f"Bearer {key}",
           "Accept": "application/vnd.github+json",
           "X-GitHub-Api-Version": "2022-11-28", "User-Agent": USER_AGENT}
    url = (f"https://api.github.com/search/code?q={quote_plus(query)}"
           f"&per_page={MAX_RESULTS_PER_SOURCE}")
    data = fetcher.get_json(url, headers=hdr)
    if data is None:
        if fetcher.live:
            code, body = (fetcher.last_error or (None, ""))
            why = (f"HTTP {code}: {body[:150]}" if code
                   else (body[:150] or "no response"))
            return SourceRun(src.key, src.label, src.surface, "blocked",
                             detail=f"GitHub code search failed — {why}",
                             queries=[query])
        return SourceRun(src.key, src.label, src.surface, "planned",
                         detail="plan-only; would query GitHub code search.",
                         queries=[query])
    items = (data.get("items") or []) if isinstance(data, dict) else []
    results: list[SearchResult] = []
    for it in items:
        repo = (it.get("repository") or {}).get("full_name", "")
        path = it.get("path", "")
        results.append(SearchResult(
            src.key, src.surface, title=f"{repo}/{path}"[:200],
            url=it.get("html_url", ""),
            snippet=_clean(f"code match in {repo}")[:300],
            meta={"repo": repo, "path": path}))
        if len(results) >= MAX_RESULTS_PER_SOURCE:
            break
    return SourceRun(src.key, src.label, src.surface,
                     "ok" if results else "empty", results=results, queries=[query])


# --- external local tools (Telepathy / scrapers) ----------------------------
# These manual sources have no clearnet API. If the operator configures a local
# command for one, Black Noir shells out to it (their tool, their responsibility)
# instead of leaving it "planned". Args are substituted safely (no shell), and it
# only runs under --live.

_CMD_ENV = {
    "telepathy": "TELEPATHY_CMD",
    "darkweb_scraper": "DARKWEB_SCRAPER_CMD",
    "torch": "TORCH_CMD",
}


def external_cmd_for(key: str) -> str:
    return os.environ.get(_CMD_ENV.get(key, ""), "").strip()


_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_BANNER_HINTS = ("an osint toolkit", "developed by", "version ")


def _clean_tool_lines(out: str) -> list[str]:
    """Strip ANSI codes and drop ASCII-art banner lines from tool output."""
    cleaned = []
    for raw in out.splitlines():
        ln = _ANSI.sub("", raw).strip()
        if not ln:
            continue
        low = ln.lower()
        if any(h in low for h in _BANNER_HINTS):
            continue
        # drop ASCII-art: lines with almost no letters/digits
        if sum(c.isalnum() for c in ln) < 3:
            continue
        cleaned.append(ln)
    return cleaned


def _run_external_tool(src: Source, query: str, fetcher: Fetcher):
    tmpl = external_cmd_for(src.key)
    if not tmpl:
        return None  # not configured -> caller falls back to "planned"
    if not fetcher.live:
        return SourceRun(src.key, src.label, src.surface, "planned",
                         detail=f"{_CMD_ENV[src.key]} configured; runs on --live.",
                         queries=[query])
    try:
        parts = shlex.split(tmpl, posix=(os.name != "nt"))
    except Exception:
        parts = tmpl.split()
    ph = ("{q}", "{query}", "{target}")
    argv = [query if p in ph else
            p.replace("{q}", query).replace("{query}", query).replace("{target}", query)
            for p in parts]
    # Resolve the executable: a path -> absolute (relative paths with '/' don't
    # resolve under Windows subprocess); a bare name -> look up on PATH.
    exe = argv[0]
    if "/" in exe or "\\" in exe:
        ap = os.path.abspath(exe)
        if os.path.exists(ap):
            argv[0] = ap
    else:
        found = shutil.which(exe)
        if found:
            argv[0] = found
    fetcher.guard.note("external-tool", _CMD_ENV[src.key],
                       f"run: {os.path.basename(argv[0])} … ({len(argv)} args)")
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=180, stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        return SourceRun(src.key, src.label, src.surface, "error",
                         detail=f"command not found: {argv[0]}", queries=[query])
    except subprocess.TimeoutExpired:
        return SourceRun(src.key, src.label, src.surface, "error",
                         detail="external tool timed out (180s).", queries=[query])
    except Exception as exc:
        return SourceRun(src.key, src.label, src.surface, "error",
                         detail=f"{type(exc).__name__}: {exc}", queries=[query])
    out = (proc.stdout or "").strip()
    if not out and proc.returncode != 0 and proc.stderr:
        out = "[stderr] " + proc.stderr.strip()
    lines = _clean_tool_lines(out)
    results = [SearchResult(src.key, src.surface, title=ln[:160], snippet=ln[:300],
                            is_onion=is_onion(ln)) for ln in lines[:MAX_RESULTS_PER_SOURCE]]
    return SourceRun(src.key, src.label, src.surface,
                     "ok" if results else "empty",
                     detail=f"external tool exit {proc.returncode}, {len(lines)} line(s).",
                     results=results, queries=[query])


# --- dispatch ---------------------------------------------------------------

def run_source(src: Source, query: str, fetcher: Fetcher) -> SourceRun:
    try:
        ext = _run_external_tool(src, query, fetcher)
        if ext is not None:
            return ext
        if src.kind == "breach":
            return _run_breach(src, query, fetcher)
        if src.kind == "serp":
            return _run_serper(src, query, fetcher)
        if src.kind == "intelx":
            return _run_intelx(src, query, fetcher)
        if src.kind == "rdap":
            return _run_rdap(src, query, fetcher)
        if src.kind == "reverseip":
            return _run_hackertarget(src, query, fetcher, "reverseiplookup")
        if src.kind == "hostsearch":
            return _run_hackertarget(src, query, fetcher, "hostsearch")
        if src.kind == "pdns":
            return _run_pdns(src, query, fetcher)
        if src.kind == "wikidata":
            return _run_wikidata(src, query, fetcher)
        if src.kind == "github":
            return _run_github(src, query, fetcher)

        url = _query_url(src, query)
        if not url:
            return SourceRun(
                src.key, src.label, src.surface, "planned",
                detail=("no clearnet query API; queued for external/manual "
                        "tooling (consent-gated). Not auto-fetched."),
            )

        body = fetcher.get(url)
        if body is None:
            err = (getattr(fetcher, "last_error", None) or (None, ""))[1] or ""
            if err.startswith("guardrail:"):
                # Refused by our OWN allow-list before any packet left the host.
                # Naming it is the difference between a fixable misconfiguration
                # and an operator concluding the target has no footprint.
                return SourceRun(
                    src.key, src.label, src.surface, "blocked",
                    detail=(f"refused by local guardrail "
                            f"({err.split(':', 1)[1]}) — this source was never "
                            f"contacted; check the allow-list, not the target"))
            if fetcher.live:  # live but the fetch failed (blocked/timeout)
                return SourceRun(
                    src.key, src.label, src.surface, "blocked",
                    detail=f"no response (blocked/timeout); query was: {url}")
            return SourceRun(
                src.key, src.label, src.surface, "planned",
                detail=f"plan-only; query URL prepared: {url}",
                results=[SearchResult(src.key, src.surface,
                                      title=f"[planned query] {query}",
                                      url=url, snippet="not fetched")],
            )
        parser = _PARSERS.get(src.key, _parse_generic)
        results = parser(body, src)
        # A 2xx-but-not-200 (DuckDuckGo answers 202 with an empty challenge
        # body) is a block, not an absence of results. Reporting it as "empty"
        # is how "we were refused" gets misread as "this target does not exist".
        status_code = getattr(fetcher, "last_status", None)
        if not results and status_code is not None and status_code != 200:
            return SourceRun(
                src.key, src.label, src.surface, "blocked",
                detail=(f"engine answered HTTP {status_code} with no parsable "
                        "results (anti-bot challenge). Not an empty result set."),
                queries=[query])
        if not results and _looks_blocked(body):
            return SourceRun(
                src.key, src.label, src.surface, "blocked",
                detail=("engine served an anti-bot/challenge page (no results "
                        "extractable). This is expected for automated queries; "
                        "Black Noir does not attempt evasion."),
                queries=[query])
        # A well-formed result set that has nothing to do with the query is a
        # decoy, not a finding. Dropping it here — rather than letting it flow
        # into the recon pile — is the difference between "this engine had
        # nothing for us" and ten unrelated pages attached to a person's name.
        # A populated page our own selector could not read is OUR bug, and it
        # must never be reported as "empty" — that is a false negative about a
        # person, manufactured by stale markup. Surfaced as `error` because the
        # fix is in this file, not in the target's footprint.
        if _looks_like_parser_break(body, src, results):
            anchors = len(re.findall(r"<a\s[^>]*href=", body, re.I))
            return SourceRun(
                src.key, src.label, src.surface, "error",
                detail=(f"PARSER BREAK (suspected): HTTP 200, {len(body):,}-byte "
                        f"body with {anchors} link(s), but the {src.key} parser "
                        f"extracted 0 results and the page does not say it found "
                        f"none. The selector is probably stale — this is a bug "
                        f"here, NOT an absence of results for this target."),
                queries=[query])
        if (results and src.key in _DECOY_PRONE
                and _looks_like_decoy(results, query)):
            return SourceRun(
                src.key, src.label, src.surface, "blocked",
                detail=(f"engine returned {len(results)} well-formed result(s) "
                        f"unrelated to the query (decoy SERP) — discarded. "
                        f"Not an empty result set."),
                queries=[query])
        return SourceRun(src.key, src.label, src.surface,
                         "ok" if results else "empty", results=results,
                         queries=[query])
    except Exception as exc:  # a connector must never break the run
        return SourceRun(src.key, src.label, src.surface, "error",
                         detail=f"{type(exc).__name__}: {exc}")
