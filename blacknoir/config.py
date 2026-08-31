"""Configuration, constants and the search-source registry.

The registry is the single source of truth about every engine Black Noir can
reach. Each entry declares:
  key           machine id
  label         human name (as the user referred to it)
  surface       "public" | "darkweb"
  category      what kind of target it is good for
  kind          "engine" | "aggregator" | "breach" | "messenger"
  clearnet      the clearnet frontend/API base (NEVER an .onion address)
  query_url     template that turns a query into a *clearnet* search-results URL
  needs_key     env var name required to authenticate, or None
  good_for      list of target types the planner should route to this source
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Optional


# Operators that free-tier SERP APIs refuse. Serper answers HTTP 400
# "Query pattern not allowed for free accounts" for any of these, which
# previously killed the source on its very first query.
_ADV_OPERATORS = re.compile(
    r'"[^"]*"|[“”]|\b(?:site|intitle|inurl|intext|filetype|related|cache):\S*|'
    r'\bOR\b|\bAND\b|(?<!\w)-(?=\w)|[()]')


def sanitize_query(q: str) -> str:
    """Strip phrase quotes and search operators, keeping the plain keywords.

    '"Alex Marsh" LinkedIn site:linkedin.com' -> 'Alex Marsh LinkedIn'
    Returns a plain-keyword query that every engine and free-tier API accepts.
    """
    if not q:
        return ""
    # keep the words inside phrase quotes, just drop the quoting
    s = re.sub(r'["“”]', " ", q)
    s = re.sub(r'\b(?:site|intitle|inurl|intext|filetype|related|cache):\S*',
               " ", s, flags=re.I)
    s = re.sub(r'\b(?:OR|AND)\b', " ", s)
    s = re.sub(r'(?<!\w)-(?=\w)', " ", s)
    s = re.sub(r'[()]', " ", s)
    return re.sub(r"\s+", " ", s).strip()


def has_advanced_operators(q: str) -> bool:
    """True when a query uses syntax a free-tier SERP API would reject."""
    return bool(q) and sanitize_query(q) != re.sub(r"\s+", " ", q).strip()


# ---- global tunables -------------------------------------------------------

DEFAULT_MODEL = os.environ.get("BLACKNOIR_MODEL", "claude-sonnet-5")
HTTP_TIMEOUT = float(os.environ.get("BLACKNOIR_HTTP_TIMEOUT", "20"))
USER_AGENT = (
    "BlackNoir-OSINT/1.0 (+research; respects robots; no-download policy)"
)
MAX_RESULTS_PER_SOURCE = int(os.environ.get("BLACKNOIR_MAX_RESULTS", "15"))
# How many AI-generated query variations each web/aggregator engine runs.
MAX_QUERIES = int(os.environ.get("BLACKNOIR_MAX_QUERIES", "4"))
MAX_RESULTS_MERGED = int(os.environ.get("BLACKNOIR_MAX_MERGED", "30"))

# Files we will NEVER fetch even from an allowed host (defence in depth).
BLOCKED_DOWNLOAD_EXT = {
    ".exe", ".msi", ".apk", ".dmg", ".bat", ".cmd", ".ps1", ".sh", ".scr",
    ".jar", ".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".bin", ".deb",
    ".rpm", ".dll", ".vbs", ".js", ".doc", ".docm", ".xlsm",
}


@dataclass(frozen=True)
class Source:
    key: str
    label: str
    surface: str
    category: str
    kind: str
    clearnet: str
    query_url: Optional[str] = None
    needs_key: Optional[str] = None
    good_for: tuple = field(default_factory=tuple)
    # Env var naming a local command for sources with no clearnet query API.
    # Without it the source can never return anything, so it is not "available"
    # — listing it as queried inflates the source count with sources that were
    # structurally incapable of answering.
    cmd_env: Optional[str] = None
    # Sources that egress from an authenticated / identity-bearing session on
    # the host — Telepathy logs in as a real Telegram account, the onion
    # crawlers fetch from the host's IP. Running one without isolation up leaks
    # the operator's real account/IP, so the pipeline refuses to run it unless
    # BOTH a VPN tunnel and Docker are active. If either is off it is dropped
    # for that run (the rest of the sweep still proceeds).
    requires_isolation: bool = False

    @property
    def available(self) -> bool:
        """True when the source can actually be queried right now."""
        if self.needs_key and not os.environ.get(self.needs_key):
            return False
        if self.cmd_env and not os.environ.get(self.cmd_env, "").strip():
            return False
        return True

    @property
    def unavailable_reason(self) -> str:
        """Why this source cannot run, for honest reporting."""
        if self.needs_key and not os.environ.get(self.needs_key):
            return f"needs {self.needs_key}"
        if self.cmd_env and not os.environ.get(self.cmd_env, "").strip():
            return (f"no clearnet query API; set {self.cmd_env} to a local "
                    f"command to enable")
        return ""


# ---- the registry ----------------------------------------------------------
# NOTE on safety: every `clearnet` / `query_url` below is an ordinary https
# host. Onion aggregators (Ahmia, Torch, ...) are reached through their public
# clearnet index, which returns metadata *about* onion sites. Black Noir reads
# that metadata; it never dereferences the onion links it finds.

REGISTRY: dict[str, Source] = {
    # -- public surface ------------------------------------------------------
    # Bing: removed 2026-08-26 as "pure noise", restored 2026-08-27 by request.
    # Two separate faults were tangled together in that removal:
    #   1. OURS — Bing was read with the generic anchor scraper, which harvests
    #      every <a> on the page (nav, related searches, tracking wrappers)
    #      rather than the result containers. Fixed: `_parse_bing` reads
    #      li.b_algo and unwraps the bing.com/ck/a click-redirects, so results
    #      now carry real destination URLs (github.com, linkedin.com, ...).
    #   2. THEIRS — and this part of the original note was correct: Bing serves
    #      randomised DECOY results to unauthenticated clients. The same query
    #      repeated three times returned three unrelated page sets (a protein
    #      bar, a piracy site, a Google login) rather than an error. Verified
    #      2026-08-27 that this is not fixable by headers: a browser
    #      User-Agent, a cookied session and retries all still decoy.
    # Two mitigations make it usable rather than harmful:
    #   * the RSS SERP (`&format=rss`) honours the query materially more often
    #     than the HTML page, and carries real destination URLs instead of
    #     bing.com/ck/a click-wrappers;
    #   * `_looks_like_decoy` discards any result set sharing no term with the
    #     query, so a decoy is reported as `blocked` instead of entering the
    #     pipeline as ten unrelated pages attached to the target's name.
    # It remains an OPPORTUNISTIC secondary — Serper stays the workhorse.
    "bing": Source(
        key="bing", label="Bing (best-effort)", surface="public",
        category="web", kind="engine",
        clearnet="https://www.bing.com",
        query_url="https://www.bing.com/search?q={q}&format=rss",
        good_for=("any", "name", "username", "domain", "email", "phone", "company"),
    ),
    #
    # DuckDuckGo is back, but as an OPPORTUNISTIC secondary only: its HTML
    # endpoint intermittently serves real results (10 clean hits) and
    # intermittently answers HTTP 202 with an empty challenge body. It is never
    # relied on — Serper is the workhorse — and a 202 is reported as `blocked`
    # rather than being mistaken for "this person does not exist".
    "duckduckgo": Source(
        key="duckduckgo", label="DuckDuckGo (best-effort)", surface="public",
        category="web", kind="engine",
        clearnet="https://duckduckgo.com",
        query_url="https://html.duckduckgo.com/html/?q={q}",
        good_for=("any", "name", "username", "domain", "email", "phone", "company"),
    ),
    "serper": Source(
        key="serper", label="Serper (Google)", surface="public",
        category="web", kind="serp",
        clearnet="https://google.serper.dev",
        query_url=None,  # queried via JSON API in the connector
        needs_key="SERPER_API_KEY",
        good_for=("any", "name", "username", "domain", "email", "phone", "company"),
    ),

    # -- dark-web surface (clearnet frontends only) --------------------------
    "ahmia": Source(
        key="ahmia", label="Ahmia.fi", surface="darkweb",
        category="onion-index", kind="aggregator",
        clearnet="https://ahmia.fi",
        query_url="https://ahmia.fi/search/?q={q}",
        good_for=("any", "keyword", "domain", "company", "leak"),
    ),
    "torch": Source(
        key="torch", label="Torch", surface="darkweb",
        category="onion-index", kind="aggregator",
        clearnet="https://torch.ampr.org",  # clearnet mirror facade
        query_url=None,  # no reliable clearnet API — needs a local command
        cmd_env="TORCH_CMD",
        requires_isolation=True,  # host-egress crawler: never run bare
        good_for=("keyword", "leak", "market"),
    ),
    # NOTE: Haystak / OnionLand / OnionSearch removed — their clearnet
    # frontends bot-block automated queries (always timed out / challenged).
    "darkweb_scraper": Source(
        key="darkweb_scraper", label="dark-web-scraper", surface="darkweb",
        category="tooling", kind="aggregator",
        clearnet="local://dark-web-scraper",
        query_url=None,  # local tooling only
        cmd_env="DARKWEB_SCRAPER_CMD",
        requires_isolation=True,  # host-egress crawler: never run bare
        good_for=("keyword", "leak", "domain"),
    ),
    "telepathy": Source(
        key="telepathy", label="Telepathy", surface="darkweb",
        category="messenger-osint", kind="messenger",
        clearnet="local://telepathy",
        query_url=None,  # Telegram OSINT toolkit, run externally with consent
        cmd_env="TELEPATHY_CMD",
        requires_isolation=True,  # logs in as a real Telegram account — gate it
        good_for=("username", "phone", "telegram", "channel"),
    ),
    "lyzem": Source(
        key="lyzem", label="Lyzem", surface="darkweb",
        category="messenger-osint", kind="messenger",
        clearnet="https://lyzem.com",
        query_url="https://lyzem.com/search?query={q}",
        good_for=("username", "keyword", "telegram", "channel"),
    ),
    # NOTE: Telegago removed — it's a Google CSE and Google bot-blocks the
    # scripted site:t.me query. Lyzem covers Telegram search keyless.
    # Intelligence X — clearnet JSON API indexing leaks, pastes, darknet
    # (Tor/I2P), whois, dumpster and more. The safe substitute for onion/leak
    # crawling: the connector reads search-record METADATA only, never the file
    # bytes. Key-gated (not host-identity egress), so no VPN/Docker needed.
    "intelx": Source(
        key="intelx", label="Intelligence X", surface="darkweb",
        category="deep-index", kind="intelx",
        clearnet="https://free.intelx.io",
        query_url=None,  # async JSON API, driven by the connector
        needs_key="INTELX_API_KEY",
        good_for=("any", "email", "domain", "company", "username",
                  "leak", "keyword"),
    ),
    # NOTE: crt.sh (cert transparency) and Wayback (archive) are NOT registered
    # as standalone sources — enrich.py's enrich_domain() already queries both
    # (plus DoH DNS) for the target and every corroborated domain, and does it
    # more robustly. Registering duplicates only double-queried two flaky
    # services. Domain recon lives in enrichment; the sources below add signals
    # enrichment does not cover.
    #
    # RDAP — keyless WHOIS/registration data (registrar, dates, nameservers).
    "rdap": Source(
        key="rdap", label="RDAP (WHOIS)", surface="public",
        category="infra", kind="rdap",
        clearnet="https://rdap.org",
        query_url="https://rdap.org/domain/{q}",
        good_for=("domain", "company"),
    ),
    # HackerTarget reverse-IP — co-hosted domains sharing the target's IP
    # (keyless; free tier ~50/day, then rate-limited).
    "reverseip": Source(
        key="reverseip", label="HackerTarget reverse-IP", surface="public",
        category="infra", kind="reverseip",
        clearnet="https://api.hackertarget.com",
        query_url="https://api.hackertarget.com/reverseiplookup/?q={q}",
        good_for=("domain", "ip"),
    ),
    # HackerTarget hostsearch — subdomain -> IP mapping (keyless).
    "hostsearch": Source(
        key="hostsearch", label="HackerTarget hostsearch", surface="public",
        category="infra", kind="hostsearch",
        clearnet="https://api.hackertarget.com",
        query_url="https://api.hackertarget.com/hostsearch/?q={q}",
        good_for=("domain",),
    ),
    # Mnemonic passive DNS — historical DNS resolutions (keyless).
    "pdns": Source(
        key="pdns", label="Mnemonic passive DNS", surface="public",
        category="infra", kind="pdns",
        clearnet="https://api.mnemonic.no",
        query_url="https://api.mnemonic.no/pdns/v3/{q}",
        good_for=("domain", "ip"),
    ),
    # Wikidata — structured entity facts for notable people/orgs (keyless).
    "wikidata": Source(
        key="wikidata", label="Wikidata", surface="public",
        category="reference", kind="wikidata",
        clearnet="https://www.wikidata.org",
        query_url="https://www.wikidata.org/w/api.php?action=wbsearchentities"
                  "&search={q}&language=en&format=json",
        good_for=("any", "name", "company", "person", "username"),
    ),
    # NOTE: psbdmp (Pastebin-dump search) evaluated 2026-08-26 and NOT added —
    # the service is defunct. psbdmp.ws no longer resolves and psbdmp.cc serves
    # a shutdown page ("That's all folks"). A source that can only ever answer
    # "blocked" is noise, so it stays out until/unless it comes back.
    #
    # GitHub code search — leaked secrets and handle-to-identity pivots. Code
    # search is auth-only on the GitHub API, so it needs a free access token.
    "github": Source(
        key="github", label="GitHub code search", surface="public",
        category="code", kind="github",
        clearnet="https://api.github.com",
        query_url=None,  # JSON API via connector
        needs_key="GITHUB_TOKEN",
        good_for=("username", "email", "domain", "company", "keyword"),
    ),
    "hibp": Source(
        key="hibp", label="Have I Been Pwned", surface="darkweb",
        category="breach", kind="breach",
        clearnet="https://haveibeenpwned.com",
        query_url="https://haveibeenpwned.com/api/v3/breachedaccount/{q}",
        needs_key=None,  # keyless for domains; per-account needs HIBP_API_KEY
        good_for=("email", "domain", "company"),
    ),
    # NOTE: DeHashed removed — no keyless endpoint; it requires a paid
    # subscription. Keyless HIBP (domains) covers the free breach signal.
    #
    # XposedOrNot — genuinely free, KEYLESS per-email breach index. This fills
    # the exact gap HIBP leaves: HIBP blocks keyless per-account (email)
    # lookups, so without a paid HIBP_API_KEY an email target produced no
    # account-level breach signal at all. XposedOrNot's public API keys on the
    # address itself and needs no key, so "is this address in a dump" — the
    # single most useful free leak signal for a person — is answerable again.
    # Rate-limited (~25/hr, 100/day per IP); email-only.
    #
    # This was added in place of four services the user asked for that turned
    # out to have NO free/public API: National Public Data (a defunct breached
    # broker, not a service), Experian's dark-web scan (a consumer web form;
    # Experian's real APIs are enterprise credit products behind a paid
    # contract), DeXpose (B2B, sales-gated) and Aura (a consumer subscription
    # app, no public API). Wiring stubs against non-existent endpoints would
    # only manufacture sources that always error — the same noise the psbdmp
    # and DeHashed removals above deliberately avoid.
    "xposed": Source(
        key="xposed", label="XposedOrNot (keyless breach)", surface="darkweb",
        category="breach", kind="breach",
        clearnet="https://xposedornot.com",
        query_url=None,  # queried via JSON API in the connector
        needs_key=None,  # genuinely keyless
        good_for=("email",),
    ),
}


def sources_for_surface(surface: str) -> list[Source]:
    return [s for s in REGISTRY.values() if s.surface == surface]


def get_source(key: str) -> Optional[Source]:
    return REGISTRY.get(key)
