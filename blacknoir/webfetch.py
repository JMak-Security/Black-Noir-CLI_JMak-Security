"""Operator-directed page fetch — read ONE page the human named, as text.

Why this does not contradict rule 4 ("the agent follows zero result links"):
that rule exists because an agent choosing its own next target from an
untrusted result page can be steered by whoever controls that page. A human
typing a URL is the opposite — the target is chosen outside the loop, by the
person responsible for the run. So this fetches exactly what was asked for and
nothing it discovers there.

Concretely, one page, once:
  * the host is authorised only because the operator named it, and only for
    this session (Guardrails.authorize_host, separately audited);
  * onion hosts, download extensions, non-HTTP schemes and private/loopback/
    metadata addresses are refused as always;
  * the body is reduced to TEXT via sanitize_message_content, so scripts and
    remote images never load and every link and image is captured as an inert
    string;
  * nothing found on the page is fetched. No depth, no recursion, no crawl.
    "Crawl this" becomes "read this, and list what it points at."
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from .config import USER_AGENT
from .guardrails import sanitize_message_content

MAX_TEXT = 20000        # characters of extracted text kept
MAX_LINKS = 60


# <script>/<style>/<noscript> bodies survive tag-stripping as plain text, so a
# page's CSS and JS arrive as "content" — the first 300 characters of this very
# page were a font stack and colour rules. Removing the blocks (not just their
# tags) is what makes the extracted text worth putting in front of a model.
_DEAD_WEIGHT = re.compile(
    r"<(script|style|noscript|template|svg)\b[^>]*>.*?</\1\s*>",
    re.I | re.S)
# Self-closing / unterminated <style> at EOF still leaves a trailing block.
_DEAD_TAIL = re.compile(r"<(script|style)\b[^>]*>.*$", re.I | re.S)


def _strip_dead_weight(html: str) -> str:
    return _DEAD_TAIL.sub(" ", _DEAD_WEIGHT.sub(" ", html or ""))


def _title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.I | re.S)
    if not m:
        return ""
    return re.sub(r"\s+", " ", re.sub("<[^>]+>", " ", m.group(1))).strip()[:200]


def fetch_page(url: str, fetcher) -> dict:
    """Fetch one operator-named page. Returns a dict; never raises.

    Keys: ok, url, status, title, text, links, images, note
    """
    url = (url or "").strip()
    if not url:
        return {"ok": False, "note": "no URL given", "url": url}
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ("http", "https"):
        return {"ok": False, "url": url,
                "note": f"scheme not allowed: {parsed.scheme}"}

    if not getattr(fetcher, "live", False):
        return {"ok": False, "url": url,
                "note": "plan-only mode — turn /live on to fetch."}

    # The operator naming the URL is the authorisation. Recorded in the audit
    # log as its own event type so a report shows plainly that this host was
    # reached because a human asked, not because it was on the curated list.
    fetcher.guard.authorize_host(url, "operator ran /fetch on this URL")

    status, body = fetcher.probe(url, headers={"User-Agent": USER_AGENT},
                                 timeout=25.0)
    if status is None:
        why = (fetcher.last_error or (None, ""))[1] or ""
        if why.startswith("guardrail:"):
            return {"ok": False, "url": url, "status": None,
                    "note": f"refused by guardrail ({why.split(':', 1)[1]})"}
        return {"ok": False, "url": url, "status": None,
                "note": "no response (blocked, timed out, or host unreachable)"}
    if status >= 400:
        return {"ok": False, "url": url, "status": status,
                "note": f"server returned HTTP {status}"}

    # Title comes from the raw body (it lives in <head>, before stripping);
    # text comes from the body with script/style blocks removed.
    page_title = _title(body or "")
    clean = sanitize_message_content(_strip_dead_weight(body or ""),
                                     is_html=True)
    links, seen = [], set()
    for href in clean.get("links", []):
        absolute = urljoin(url, href)
        if not absolute.lower().startswith(("http://", "https://")):
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        links.append(absolute)
        if len(links) >= MAX_LINKS:
            break

    return {
        "ok": True, "url": url, "status": status, "title": page_title,
        "text": clean.get("text", "")[:MAX_TEXT],
        "links": links, "images": clean.get("images", [])[:20],
        "note": ("read as text; scripts and images were not loaded and no link "
                 "on this page was followed"),
    }


def summarize(page: dict, width: int = 400) -> str:
    """Short human line for the CLI."""
    if not page.get("ok"):
        return f"fetch failed — {page.get('note', 'unknown error')}"
    return (f"{page.get('title') or '(untitled)'} · "
            f"{len(page.get('text', ''))} chars of text, "
            f"{len(page.get('links', []))} link(s) listed (none followed)")
