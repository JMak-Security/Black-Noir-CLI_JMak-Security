"""Native enrichment — turn key entities into structured intel automatically.

For a domain / IP / BTC address / username (the target, or a surfaced entity),
Black Noir queries the relevant KEYLESS official APIs and folds the results into
the graph — instead of only handing you a runbook link.

All hosts are on the guardrail allow-list, all calls are JSON reads (never a file
download), and it only runs on --live. Onion/Tor is still never touched.

Sources (all keyless):
  domain   -> crt.sh (subdomains/certs) + Google DoH (MX/NS/TXT) + Wayback
  ip       -> Shodan InternetDB (open ports, CPEs, hostnames)
  btc      -> Blockstream (balance, tx count)
  username -> GitHub API + Reddit about.json (account presence + metadata)
"""

from __future__ import annotations

import os
import re

from .config import MAX_RESULTS_PER_SOURCE, USER_AGENT
from .entities import NOISE_DOMAINS
from .models import SearchResult, SourceRun


def _is_noise_domain(val: str, extra: set | None = None) -> bool:
    """A search-infrastructure / platform / CDN host — never worth enriching.

    crt.sh-ing linkedin.com or wikidata.org for a *person* only manufactures
    junk subdomain nodes (cctld.linkedin.com, dyna.wikimedia.org) that have
    nothing to do with the target. These are the search sources' own domains,
    not the target's, so they must not fan out enrichment.

    `extra` is the per-run set the AI flagged as infra; the static NOISE_DOMAINS
    is the always-on floor and `extra` extends it for this investigation.
    """
    low = (val or "").strip().lower().strip(".")
    pools = (NOISE_DOMAINS, {str(n).strip().lower().strip(".")
                             for n in (extra or ()) if n})
    return any(low == n or low.endswith("." + n)
               for pool in pools for n in pool)

_UA = {"User-Agent": USER_AGENT}


def _run(key, label, results, status=None):
    return SourceRun(key, label, "public",
                     status or ("ok" if results else "empty"), results=results)


# --- domain -----------------------------------------------------------------

# crt.sh can be slow; keep enrichment responsive with a tighter per-call budget.
_ENRICH_TIMEOUT = 12.0


def enrich_domain(domain: str, fetcher) -> SourceRun:
    results: list[SearchResult] = []
    # certificate transparency -> subdomains
    data = fetcher.get_json(f"https://crt.sh/?q=%25.{domain}&output=json",
                            timeout=_ENRICH_TIMEOUT)
    if data is None and not fetcher.live:
        return _run("enrich_domain", "Domain recon", [], "planned")
    subs = set()
    if isinstance(data, list):
        for row in data:
            for nm in str(row.get("name_value", "")).split("\n"):
                nm = nm.strip().lower().lstrip("*.")
                if nm.endswith(domain) and nm != domain:
                    subs.add(nm)
    for s in sorted(subs)[:MAX_RESULTS_PER_SOURCE]:
        results.append(SearchResult("enrich_domain", "public",
                       title=f"subdomain: {s}", url=f"https://{s}",
                       meta={"kind": "subdomain"}))
    # DNS records via Google DoH
    for typ in ("MX", "NS", "TXT"):
        d = fetcher.get_json(f"https://dns.google/resolve?name={domain}&type={typ}",
                             timeout=_ENRICH_TIMEOUT)
        for ans in (d or {}).get("Answer", [])[:5]:
            results.append(SearchResult("enrich_domain", "public",
                           title=f"DNS {typ}: {str(ans.get('data',''))[:90]}"))
    # Wayback earliest/closest snapshot
    wb = fetcher.get_json(f"https://archive.org/wayback/available?url={domain}",
                          timeout=_ENRICH_TIMEOUT)
    snap = ((wb or {}).get("archived_snapshots") or {}).get("closest") or {}
    if snap.get("url"):
        results.append(SearchResult("enrich_domain", "public",
                       title=f"Wayback snapshot {snap.get('timestamp','')}",
                       url=snap.get("url", "")))
    return _run("enrich_domain", "Domain recon (crt.sh/DNS/Wayback)", results)


# --- ip ---------------------------------------------------------------------

def enrich_ip(ip: str, fetcher) -> SourceRun:
    d = fetcher.get_json(f"https://internetdb.shodan.io/{ip}")
    if d is None:
        return _run("enrich_ip", "IP recon", [],
                    "planned" if not fetcher.live else "empty")
    if isinstance(d, dict) and d.get("__status__") == 404:
        return _run("enrich_ip", "IP recon (Shodan InternetDB)", [], "empty")
    ports = d.get("ports", []) if isinstance(d, dict) else []
    results = [SearchResult("enrich_ip", "public",
               title=f"{ip} — open ports: {ports}",
               snippet=f"hostnames: {', '.join(d.get('hostnames', [])[:5])} · "
                       f"cpes: {', '.join(d.get('cpes', [])[:5])} · "
                       f"vulns: {', '.join(d.get('vulns', [])[:5])}",
               url=f"https://www.shodan.io/host/{ip}")]
    return _run("enrich_ip", "IP recon (Shodan InternetDB)", results)


# --- btc --------------------------------------------------------------------

def enrich_btc(addr: str, fetcher) -> SourceRun:
    d = fetcher.get_json(f"https://blockstream.info/api/address/{addr}")
    if not d or not isinstance(d, dict):
        return _run("enrich_btc", "BTC address", [],
                    "planned" if not fetcher.live else "empty")
    cs = d.get("chain_stats", {})
    funded, spent = cs.get("funded_txo_sum", 0), cs.get("spent_txo_sum", 0)
    bal = (funded - spent) / 1e8
    total_in = funded / 1e8
    results = [SearchResult("enrich_btc", "public",
               title=f"BTC {addr[:14]}… balance {bal:.8f} BTC",
               snippet=f"{cs.get('tx_count', 0)} txs · total received "
                       f"{total_in:.8f} BTC",
               url=f"https://blockstream.info/address/{addr}",
               meta={"balance": bal, "tx_count": cs.get("tx_count", 0)})]
    return _run("enrich_btc", "BTC address (Blockstream)", results)


# --- username ---------------------------------------------------------------

def enrich_username(u: str, fetcher) -> SourceRun:
    u = u.lstrip("@")
    results = []
    gh = fetcher.get_json(f"https://api.github.com/users/{u}", headers=_UA)
    if gh and isinstance(gh, dict) and gh.get("login"):
        results.append(SearchResult("enrich_username", "public",
                       title=f"GitHub: {gh.get('login')} — {gh.get('name') or ''}",
                       url=gh.get("html_url", ""),
                       snippet=f"repos {gh.get('public_repos')} · "
                               f"{gh.get('bio') or ''}"[:200]))
    rd = fetcher.get_json(f"https://www.reddit.com/user/{u}/about.json", headers=_UA)
    rdd = (rd or {}).get("data") if isinstance(rd, dict) else None
    if rdd and rdd.get("name"):
        results.append(SearchResult("enrich_username", "public",
                       title=f"Reddit: u/{rdd.get('name')}",
                       url=f"https://www.reddit.com/user/{rdd.get('name')}",
                       snippet=f"karma {rdd.get('total_karma', '?')}"))
    # Bluesky (keyless public AppView) — bare handles resolve as u.bsky.social
    actor = u if "." in u else f"{u}.bsky.social"
    bs = fetcher.get_json(
        f"https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={actor}",
        headers=_UA)
    if bs and isinstance(bs, dict) and bs.get("handle"):
        results.append(SearchResult("enrich_username", "public",
                       title=f"Bluesky: @{bs.get('handle')} — "
                             f"{bs.get('displayName') or ''}",
                       url=f"https://bsky.app/profile/{bs.get('handle')}",
                       snippet=f"followers {bs.get('followersCount', '?')} · "
                               f"{(bs.get('description') or '')}"[:180]))
    # Mastodon (mastodon.social instance, keyless)
    ms = fetcher.get_json(
        f"https://mastodon.social/api/v1/accounts/lookup?acct={u}", headers=_UA)
    if ms and isinstance(ms, dict) and ms.get("username"):
        results.append(SearchResult("enrich_username", "public",
                       title=f"Mastodon: @{ms.get('username')}@mastodon.social",
                       url=ms.get("url", ""),
                       snippet=f"followers {ms.get('followers_count', '?')} · "
                               f"{(ms.get('note') or '')}"[:160]))
    status = None
    if not results and not fetcher.live:
        status = "planned"
    return _run("enrich_username",
                "Handle presence (GitHub/Reddit/Bluesky/Mastodon)",
                results, status)


# --- optional KEYED enrichers (run only when their key is set) ---------------

def enrich_ip_shodan(ip: str, fetcher, key: str) -> SourceRun:
    d = fetcher.get_json(f"https://api.shodan.io/shodan/host/{ip}?key={key}")
    if not d or not isinstance(d, dict) or d.get("__status__") == 404:
        return _run("enrich_shodan", "IP recon (Shodan full)", [], "empty")
    ports = d.get("ports", [])
    products = sorted({s.get("product", "") for s in d.get("data", [])
                       if s.get("product")})
    r = SearchResult("enrich_shodan", "public",
                     title=f"{ip} — Shodan: {d.get('org') or d.get('isp') or ''}"
                           f" · ports {ports}",
                     snippet=f"os: {d.get('os') or '?'} · "
                             f"products: {', '.join(products[:6])} · "
                             f"vulns: {', '.join(list(d.get('vulns', []))[:6])}",
                     url=f"https://www.shodan.io/host/{ip}")
    return _run("enrich_shodan", "IP recon (Shodan full)", [r])


def enrich_phone_numverify(number: str, fetcher, key: str) -> SourceRun:
    digits = re.sub(r"\D", "", number)
    # Numverify free plan is HTTP-only.
    d = fetcher.get_json(
        f"http://apilayer.net/api/validate?access_key={key}&number={digits}")
    if not d or not isinstance(d, dict) or not d.get("valid"):
        return _run("enrich_numverify", "Phone intel (Numverify)", [], "empty")
    r = SearchResult("enrich_numverify", "public",
                     title=f"+{d.get('country_prefix','').lstrip('+')}{digits} — "
                           f"{d.get('carrier') or 'unknown carrier'} "
                           f"({d.get('line_type') or '?'})",
                     snippet=f"country: {d.get('country_name','?')} · "
                             f"location: {d.get('location','?')} · "
                             f"local: {d.get('local_format','')}")
    return _run("enrich_numverify", "Phone intel (Numverify)", [r])


def enrich_intelx(term: str, fetcher, key: str) -> SourceRun:
    """Intelligence X — 2-step async search. Best-effort; degrades to empty."""
    hdr = {"x-key": key, "User-Agent": USER_AGENT}
    init = fetcher.post("https://2.intelx.io/intelligent/search",
                        json_body={"term": term, "maxresults": 10, "media": 0,
                                   "sort": 2, "terminate": []},
                        headers=hdr, as_json=True)
    sid = (init or {}).get("id") if isinstance(init, dict) else None
    if not sid:
        return _run("enrich_intelx", "Breach/leak (Intelligence X)", [], "empty")
    res = fetcher.get_json(
        f"https://2.intelx.io/intelligent/search/result?id={sid}", headers=hdr)
    recs = (res or {}).get("records", []) if isinstance(res, dict) else []
    results = []
    for rec in recs[:MAX_RESULTS_PER_SOURCE]:
        results.append(SearchResult("enrich_intelx", "public",
                       title=f"IntelX: {rec.get('name', '')[:90]}",
                       snippet=f"bucket: {rec.get('bucket','')} · "
                               f"date: {rec.get('date','')}"))
    return _run("enrich_intelx", "Breach/leak (Intelligence X)", results)


# --- orchestrator -----------------------------------------------------------

def run_enrichment(target: str, target_type: str, inv, fetcher,
                   cap: int = 5, domain_cap: int = 2,
                   extra_noise: set | None = None) -> list[SourceRun]:
    runs, done = [], set()
    shodan_key = os.environ.get("SHODAN_API_KEY", "").strip()
    numverify_key = os.environ.get("NUMVERIFY_API_KEY", "").strip()
    intelx_key = os.environ.get("INTELX_API_KEY", "").strip()
    domain_hits = [0]  # crt.sh is the slow long-pole — bound it hard

    def do(kind: str, val: str, is_target: bool = False):
        k = (kind, val.lower())
        if k in done or len(done) >= cap:
            return
        if kind in ("domain", "company"):
            # never crt.sh/DNS a search-infrastructure or platform host: for a
            # person target these only produce junk subdomain nodes. Static list
            # + the AI-flagged per-run set.
            if not is_target and _is_noise_domain(val, extra_noise):
                return
            if domain_hits[0] >= domain_cap:
                return
            domain_hits[0] += 1
        done.add(k)
        if kind in ("domain", "company"):
            runs.append(enrich_domain(val, fetcher))
        elif kind == "ip":
            runs.append(enrich_ip(val, fetcher))
            if shodan_key:
                runs.append(enrich_ip_shodan(val, fetcher, shodan_key))
        elif kind == "btc":
            runs.append(enrich_btc(val, fetcher))
        elif kind in ("username", "handle"):
            runs.append(enrich_username(val, fetcher))
        elif kind == "phone":
            # Structure first, and unconditionally: it needs no key and no
            # network, so a phone target stops producing a blank enrichment
            # section when NUMVERIFY_API_KEY is absent. The keyed lookup adds
            # carrier/line-type from the operator's own data when available.
            from .phone import run_phone
            runs.append(run_phone(val))
            if numverify_key:
                runs.append(enrich_phone_numverify(val, fetcher, numverify_key))

    do(target_type, target, is_target=True)
    # only enrich CORROBORATED entities (weight >= 2) so a username search
    # doesn't fan out crt.sh across every random domain a SERP scraped.
    for e in sorted(inv.entities, key=lambda e: -e.weight):
        if getattr(e, "weight", 1) < 2 and e.first_seen != "target":
            continue
        do(e.kind, e.value)

    # cross-platform username sweep — only for a bare-handle primary target
    # (heavier: ~25 requests), plus optional IntelX breach search on the target.
    if target_type in ("username", "handle"):
        from .username_sweep import sweep_username
        runs.append(sweep_username(target, fetcher))
    # IntelX is NOT queried here any more: the first-class `intelx` source
    # (connectors._run_intelx) already searches it on the target with multi-key
    # failover and the correct free-tier base. Querying it here too spent a
    # second search credit per run and used a hardcoded paid-instance base that
    # silently returned empty on free keys. `enrich_intelx` is kept for callers
    # that pass an explicit key but is no longer auto-run.
    _ = intelx_key  # retained for signature/back-compat; intentionally unused

    return [r for r in runs if r]
