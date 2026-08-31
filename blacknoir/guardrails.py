"""Central safety enforcement.

Every outbound network action in Black Noir passes through `Guardrails`.
Policy (non-negotiable, enforced in code):

  1. NO onion fetches. `.onion` hosts are never dereferenced. When an index
     returns onion links we keep them only as *text metadata*.
  2. NO downloads. Binary/archive/document/script URLs are refused.
  3. NO untrusted hosts. Only hosts on the clearnet allow-list (derived from
     the source registry) may be contacted.
  4. NO clicking. The agent follows zero result links; it only reads the
     search-index pages themselves.
  5. Everything refused is logged so the run is auditable.
"""

from __future__ import annotations

import html as _htmllib
import os
import re as _re
import threading
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .config import BLOCKED_DOWNLOAD_EXT, REGISTRY


_INTERNAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost",
                   "metadata", "metadata.google.internal", "instance-data"}


def _is_internal_host(host: str) -> bool:
    """True for loopback / private / link-local / metadata targets.

    Checked on the literal host in the URL. A hostname that RESOLVES into a
    private range is not caught here — doing that properly needs a resolve-then-
    pin-the-socket flow, which `requests` does not expose. This blocks the
    realistic cases (typed IP literals, localhost, the cloud metadata address)
    rather than claiming to be a complete SSRF defence.
    """
    h = (host or "").lower().strip("[]")
    if not h or h in _INTERNAL_NAMES or h.endswith(".local"):
        return True
    try:
        import ipaddress
        ip = ipaddress.ip_address(h)
        return (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified)
    except ValueError:
        return False        # not an IP literal — a normal hostname


@dataclass
class GuardEvent:
    action: str      # "allow" | "block"
    url: str
    reason: str


class Guardrails:
    def __init__(self) -> None:
        self.events: list[GuardEvent] = []
        # Guards the audit log so parallel probes (username sweep) can't
        # interleave or drop events — the log is the safety proof, so it stays
        # complete and internally consistent under threads.
        self._lock = threading.Lock()
        # Allow-list of hosts we may contact = every clearnet host in registry.
        # Both `clearnet` AND `query_url` are harvested: a source's landing page
        # and its query endpoint are often different hosts (DuckDuckGo advertises
        # duckduckgo.com but queries html.duckduckgo.com), and matching below is
        # exact — so taking only `clearnet` silently blocks the source on every
        # single query. Deriving from both keeps the allow-list honest as the
        # registry grows.
        self.allowed_hosts: set[str] = set()
        for src in REGISTRY.values():
            for base in (src.clearnet, src.query_url):
                host = self._host(base)
                if host:
                    self.allowed_hosts.add(host)
        # A few well-known clearnet hosts used by the aggregators' result pages
        self.allowed_hosts.update({
            "www.google.com", "google.com", "duckduckgo.com",
            "www.bing.com", "haveibeenpwned.com",
        })
        # Reverse-image search endpoints (real uploads + prepared upload links).
        self.allowed_hosts.update({
            "saucenao.com", "iqdb.org", "lens.google.com",
            "images.google.com", "yandex.com", "www.yandex.com",
            "tineye.com", "www.tineye.com",
        })
        # Serper — Google SERP API.
        self.allowed_hosts.add("google.serper.dev")
        # Intelligence X — free + paid API instances (base is env-configurable).
        self.allowed_hosts.update({"free.intelx.io", "2.intelx.io",
                                   "intelx.io"})
        # GitHub code search API.
        self.allowed_hosts.update({"api.github.com", "github.com"})
        # Keyless infra/reference sources + crt.sh & Wayback (used by enrich.py).
        self.allowed_hosts.update({"rdap.org", "api.hackertarget.com",
                                   "api.mnemonic.no", "www.wikidata.org",
                                   "wikidata.org", "crt.sh", "web.archive.org",
                                   "archive.org"})
        # Native enrichment — keyless official APIs (JSON reads only, no files).
        self.allowed_hosts.update({
            "crt.sh",                    # certificate transparency / subdomains
            "dns.google",                # DNS-over-HTTPS (MX/NS/TXT)
            "archive.org",               # Wayback availability
            "internetdb.shodan.io",      # keyless IP port/CPE data
            "blockstream.info",          # BTC address balance/tx
            "api.github.com",            # GitHub user presence
            "www.reddit.com",            # Reddit account presence (about.json)
            "public.api.bsky.app",       # Bluesky profile (keyless)
            "mastodon.social",           # Mastodon account lookup (keyless)
        })
        # Pwned Passwords range API — keyless, k-anonymity. Distinct host from
        # haveibeenpwned.com and must be listed separately or the check is
        # refused by our own allow-list before a packet leaves.
        self.allowed_hosts.add("api.pwnedpasswords.com")
        # Optional KEYED enrichers — only ever called when their key is present.
        self.allowed_hosts.update({
            "api.shodan.io",             # Shodan full host (SHODAN_API_KEY)
            "apilayer.net",              # Numverify phone (NUMVERIFY_API_KEY)
            "2.intelx.io",               # Intelligence X (INTELX_API_KEY)
        })
        # Cross-platform username sweep — curated social hosts (presence checks).
        from .username_sweep import SWEEP_HOSTS
        self.allowed_hosts.update(SWEEP_HOSTS)

        # Hosts the OPERATOR explicitly named this session (see authorize_host).
        # Kept separate from `allowed_hosts` so the audit log — and anyone
        # reading this class — can tell a curated source from a one-off the
        # human asked for.
        self.operator_hosts: set[str] = set()

    # -- public API ----------------------------------------------------------

    def authorize_host(self, url: str, reason: str = "operator-supplied URL") -> str:
        """Permit one host because the OPERATOR asked for it by name.

        Rule 4 forbids the agent following links it discovered — that is the
        agent choosing its own targets from untrusted result pages. A human
        typing a URL is not that: it is a directed instruction, and the host is
        authorised by the act of naming it. The distinction is the whole reason
        this is a separate method with its own audit entry rather than a hole
        in `allowed_hosts`.

        Everything else still applies: onion, download extensions, private-range
        addresses and non-HTTP schemes are refused for these hosts too.
        """
        host = (urlparse(url).hostname or "").lower()
        if host:
            self.operator_hosts.add(host)
            self.note("authorize", url, reason)
        return host

    def can_fetch(self, url: str) -> tuple[bool, str]:
        """Return (allowed, reason) and record the decision."""
        allowed, reason = self._evaluate(url)
        with self._lock:
            self.events.append(
                GuardEvent("allow" if allowed else "block", url, reason)
            )
        return allowed, reason

    def note(self, action: str, url: str, reason: str) -> None:
        with self._lock:
            self.events.append(GuardEvent(action, url, reason))

    @property
    def blocks(self) -> list[GuardEvent]:
        return [e for e in self.events if e.action == "block"]

    def summary(self) -> dict:
        return {
            "total": len(self.events),
            "allowed": sum(1 for e in self.events if e.action == "allow"),
            "blocked": len(self.blocks),
            "uploads": sum(1 for e in self.events if e.action == "upload"),
            "blocked_urls": [
                {"url": e.url, "reason": e.reason} for e in self.blocks
            ],
        }

    # -- internals -----------------------------------------------------------

    def _evaluate(self, url: str) -> tuple[bool, str]:
        if not url or "://" not in url:
            return False, "malformed-url"
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()

        if scheme not in ("http", "https"):
            return False, f"scheme-not-allowed:{scheme}"
        if host.endswith(".onion"):
            return False, "onion-fetch-forbidden"
        if not host:
            return False, "no-host"
        # download / executable extension check
        path = parsed.path.lower()
        _, ext = os.path.splitext(path)
        if ext in BLOCKED_DOWNLOAD_EXT:
            return False, f"download-blocked:{ext}"
        # Private/loopback/link-local targets are refused for EVERY host,
        # allow-listed or operator-named. Without this, an operator-directed
        # fetch turns the tool into an SSRF primitive pointed at the machine it
        # runs on — cloud metadata at 169.254.169.254, admin panels on
        # localhost, anything on the LAN.
        if _is_internal_host(host):
            return False, f"internal-address-blocked:{host}"
        if host not in self.allowed_hosts and host not in self.operator_hosts:
            return False, f"host-not-allowlisted:{host}"
        return True, "ok"

    @staticmethod
    def _host(base: str | None) -> str | None:
        # `query_url` is None for API-queried sources, and a "local://..."
        # pseudo-URL marks a source run by a local command — neither is a host.
        if not base or base.startswith("local://"):
            return None
        try:
            return (urlparse(base).hostname or "").lower() or None
        except Exception:
            return None


def is_onion(value: str) -> bool:
    v = value.lower()
    return ".onion" in v


# --- message/email content sanitizer ---------------------------------------
# The "no virus" rule: message bodies are read as TEXT only. Links and remote
# images are captured as inert strings and NEVER fetched; attachments are never
# opened; HTML is stripped so nothing auto-loads.

_URL_RE = _re.compile(r'https?://[^\s"\'<>)\]]+', _re.I)
_TAG_RE = _re.compile(r'<[^>]+>')
_HREF_RE = _re.compile(r'href=["\']([^"\']+)["\']', _re.I)
_IMG_RE = _re.compile(r'<img[^>]+src=["\']([^"\']+)["\']', _re.I)


def sanitize_message_content(raw: str, is_html: bool = False) -> dict:
    """Return {text, links, images} with NOTHING fetched or opened.

    - HTML is stripped to plain text; href/src are extracted as inert text.
    - Remote images are listed (as URLs) but never loaded.
    - Bare URLs in text are captured as inert links.
    """
    raw = raw or ""
    links: list[str] = []
    images: list[str] = []
    looks_html = is_html or bool(_re.search(r"<(a|img|div|p|br|table)\b", raw, _re.I))
    if looks_html:
        links.extend(_HREF_RE.findall(raw))
        images.extend(_IMG_RE.findall(raw))
        text = _htmllib.unescape(_TAG_RE.sub(" ", raw))
    else:
        text = raw
    for m in _URL_RE.findall(text):
        if m not in links:
            links.append(m)
    text = _re.sub(r"\s+", " ", text).strip()
    return {"text": text,
            "links": list(dict.fromkeys(links)),
            "images": list(dict.fromkeys(images))}
