"""Target-type pivot toolkits.

Given a target (and the entities found), produce ready-to-open clearnet OSINT
tool links appropriate for its type — phone, email, username, domain, ip, btc,
name. These are *manual* pivots: the operator opens them; Black Noir never
fetches them (consistent with the no-download / no-follow guardrail).
"""

from __future__ import annotations

import re
from urllib.parse import quote_plus


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def _phone(t: str, d: str) -> list[tuple[str, str]]:
    enc = quote_plus(t)
    tools = [
        ("Google (exact)", f"https://www.google.com/search?q=%22{enc}%22"),
        ("FreeCarrierLookup (carrier/HLR)", "https://freecarrierlookup.com/"),
        ("NumLookup", f"https://www.numlookup.com/results?phone={d}"),
        ("Sync.me / Truecaller (manual)", "https://sync.me/"),
        ("WhatsApp check", f"https://wa.me/{d}"),
        ("Should I Answer (scam DB)", "https://www.shouldianswer.com/"),
    ]
    if t.replace(" ", "").startswith(("+852", "852")):
        tools.append(("HK junk-call DB", "https://hkjunkcall.com/"))
    return tools


def _email(t: str) -> list[tuple[str, str]]:
    enc = quote_plus(t)
    return [
        ("Have I Been Pwned", f"https://haveibeenpwned.com/account/{enc}"),
        ("Epieos (reverse email)", "https://epieos.com/"),
        ("Hunter email verifier", f"https://hunter.io/email-verifier/{enc}"),
        ("Gravatar check", "https://gravatar.com/"),
        ("Google (exact)", f"https://www.google.com/search?q=%22{enc}%22"),
    ]


def _username(t: str) -> list[tuple[str, str]]:
    u = t.lstrip("@")
    return [
        ("WhatsMyName", "https://whatsmyname.app/"),
        ("Namechk", "https://namechk.com/"),
        ("InstantUsername", f"https://instantusername.com/#/?q={quote_plus(u)}"),
        ("GitHub", f"https://github.com/{u}"),
        ("X / Twitter", f"https://x.com/{u}"),
        ("Instagram", f"https://www.instagram.com/{u}/"),
        ("Telegram", f"https://t.me/{u}"),
        ("Reddit", f"https://www.reddit.com/user/{u}"),
    ]


def _domain(t: str) -> list[tuple[str, str]]:
    return [
        ("WHOIS (who.is)", f"https://who.is/whois/{t}"),
        ("crt.sh (subdomains/certs)", f"https://crt.sh/?q={t}"),
        ("DNSDumpster", "https://dnsdumpster.com/"),
        ("urlscan.io", f"https://urlscan.io/domain/{t}"),
        ("Wayback Machine", f"https://web.archive.org/web/*/{t}"),
        ("BuiltWith", f"https://builtwith.com/{t}"),
        ("HIBP breaches (domain)", f"https://haveibeenpwned.com/PwnedWebsites"),
    ]


def _ip(t: str) -> list[tuple[str, str]]:
    return [
        ("Shodan", f"https://www.shodan.io/host/{t}"),
        ("ipinfo.io", f"https://ipinfo.io/{t}"),
        ("AbuseIPDB", f"https://www.abuseipdb.com/check/{t}"),
        ("Censys", f"https://search.censys.io/hosts/{t}"),
    ]


def _btc(t: str) -> list[tuple[str, str]]:
    return [
        ("Blockchair", f"https://blockchair.com/bitcoin/address/{t}"),
        ("Blockchain.com", f"https://www.blockchain.com/explorer/addresses/btc/{t}"),
        ("OXT / Walletexplorer", "https://www.walletexplorer.com/"),
    ]


def _name(t: str) -> list[tuple[str, str]]:
    enc = quote_plus(t)
    return [
        ("Google (exact)", f"https://www.google.com/search?q=%22{enc}%22"),
        ("LinkedIn (via Google)",
         f"https://www.google.com/search?q=site:linkedin.com+%22{enc}%22"),
        ("Facebook search", f"https://www.facebook.com/search/top?q={enc}"),
        ("Pipl-style / TruePeopleSearch (manual)", "https://www.truepeoplesearch.com/"),
    ]


_BUILDERS = {
    "phone": lambda t: _phone(t, _digits(t)),
    "email": lambda t: _email(t),
    "username": lambda t: _username(t),
    "handle": lambda t: _username(t),
    "domain": lambda t: _domain(t),
    "company": lambda t: _domain(t),
    "ip": lambda t: _ip(t),
    "btc": lambda t: _btc(t),
    "name": lambda t: _name(t),
    "person": lambda t: _name(t),
}


def pivot_toolkit(target: str, target_type: str,
                  entities=None) -> dict[str, list[tuple[str, str]]]:
    """Return {type: [(label, url), ...]} for the target and any typed entities."""
    out: dict[str, list[tuple[str, str]]] = {}
    tt = (target_type or "").lower()

    # target itself
    if tt in _BUILDERS:
        out[tt] = _BUILDERS[tt](target)
    elif tt == "other" and 7 <= len(_digits(target)) <= 15 and \
            not any(c.isalpha() for c in target):
        out["phone"] = _phone(target, _digits(target))

    # high-value typed entities that were surfaced (email/username/domain/btc)
    seen = set(out)
    for e in (entities or []):
        k = e.kind
        if k in ("email", "username", "handle", "domain", "btc", "ip") \
                and k not in seen:
            seen.add(k)
            out[k] = _BUILDERS[k](e.value)
    return out
