"""Link a real name to an account handle — the "Alex Marsh -> AMarsh-Sec" step.

HOW THAT LINK IS ACTUALLY MADE
------------------------------
It is tempting to assume a search engine *deduced* "AMarsh-Sec" from "Alex
Marsh". It did not, and building on that assumption produces a machine that
confidently attributes strangers' accounts to people.

What actually happens is far more boring: the GitHub profile's own `name` field
says "Alex Marsh". Both strings are on the same indexed page, so the engine is
doing string matching, not inference. The link was PUBLISHED by the account
owner; the engine only noticed it.

That distinction sets this module's rule:

    A name<->handle link is reported ONLY when the account's own public
    metadata names the person.

Enumeration alone ("amarsh", "alexmarsh", "makj"…) produces plausible handles that
mostly belong to OTHER PEOPLE. Existence is not identity: `github.com/amarsh`
existing tells you nothing about Alex Marsh. So permutations here are used only
to generate candidates for confirmation, never as findings in themselves — and
an unconfirmed hit is reported as explicitly NOT linked.

This constraint is load-bearing, not decorative. It is what makes the module
useful for auditing your own exposure — "your GitHub publicly states your real
name, and that is what connects your handle to you" is exactly the finding a
self-audit needs — while making it structurally useless for unmasking an
anonymous account, because an anonymous account does not state a name. The
accounts someone would want to de-anonymise are precisely the ones that fail
the check.
"""

from __future__ import annotations

import re
import unicodedata

from .config import USER_AGENT
from .models import SearchResult, SourceRun

_UA = {"User-Agent": USER_AGENT}

# Keyless endpoints that return an account's self-declared display name.
# Reddit is deliberately absent: its about.json carries no real-name field, so
# it can establish existence but never confirmation.
_NAME_SOURCES = (
    ("GitHub", "https://api.github.com/users/{u}",
     ("name",), "https://github.com/{u}"),
    ("Bluesky",
     "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={u}",
     ("displayName",), "https://bsky.app/profile/{u}"),
    ("Mastodon", "https://mastodon.social/api/v1/accounts/lookup?acct={u}",
     ("display_name",), "https://mastodon.social/@{u}"),
)

_SEPS = ("", ".", "_", "-")


def _norm(s: str) -> str:
    """Casefold, strip accents and punctuation — for comparing names only.

    Keeps every alphanumeric character, not just ASCII. An `[^a-z0-9]` filter
    erased CJK entirely: "王婧妍" normalised to "", so a native-script alias
    could never match anything and was silently dead weight — on exactly the
    targets where it is the strongest identifier, since a romanised Hong Kong
    name is shared by hundreds of strangers while the Chinese form is not.

    NFKD + combining-strip still folds accents, so "José" and "Jose" compare
    equal; `.isalnum()` is Unicode-aware, so Han, Kana, Hangul and Cyrillic all
    survive.
    """
    s = unicodedata.normalize("NFKD", s or "")
    s = "".join(c for c in s if not unicodedata.combining(c))
    s = "".join(c if c.isalnum() else " " for c in s.lower())
    return re.sub(r"\s+", " ", s).strip()


def _ascii_handle(h: str) -> bool:
    """Account handles are ASCII on every platform we probe.

    `_norm` now preserves CJK, which is right for comparing names and wrong for
    generating handles: "王婧妍" is a valid normalised name but can never be a
    GitHub username, so probing it only burns a request on a guaranteed 404.
    """
    return bool(h) and h.isascii()


def handle_permutations(name: str, limit: int = 24) -> list:
    """Plausible handles for a Western-order personal name.

    Deliberately conservative. The real "AMarsh-Sec" carries a `-Security`
    suffix that no enumerator would guess, which is the point: enumeration is a
    weak supplement, not the mechanism. The mechanism is finding the handle in
    search results and confirming it against the account's own name field.
    """
    parts = [p for p in _norm(name).split() if len(p) > 1]
    if len(parts) < 2:
        # Single-token path must honour the ASCII rule too — it is the one a
        # CJK-only name takes, and returning "王婧妍" as a handle candidate
        # spends a probe that every platform will 404.
        return [p for p in parts if _ascii_handle(p)][:limit]
    first, last = parts[0], parts[-1]
    fi, li = first[0], last[0]
    out: list = []

    # Three-token names (romanised CJK especially: "Wong Jing Yi", where Wong is
    # the surname and "Jing Yi" the given name) are mangled by first/last logic
    # alone — it yields "wongyi", silently dropping the middle token. Treat the
    # name as (surname, given-name) in both orders. These lead rather than
    # trail: the full concatenation is the most common real handle form for such
    # names, and the caller's cap would otherwise truncate them away.
    if len(parts) > 2:
        head, tail = parts[0], "".join(parts[1:])      # wong / jingyi
        lead, end = "".join(parts[:-1]), parts[-1]     # wongjing / yi
        initials = "".join(p[0] for p in parts)        # wjy
        out += ["".join(parts), f"{tail}{head}"]
        for sep in _SEPS:
            out += [f"{head}{sep}{tail}", f"{tail}{sep}{head}",
                    f"{lead}{sep}{end}"]
        out += [initials, f"{initials[0]}{tail}", f"{tail}{initials[0]}"]

    for sep in _SEPS:
        out += [f"{first}{sep}{last}", f"{fi}{sep}{last}",
                f"{last}{sep}{first}", f"{first}{sep}{li}"]
    out += [f"{last}{fi}", first, last]
    seen, uniq = set(), []
    for h in out:
        h = h.strip("._-")
        if (h and h not in seen and 2 <= len(h) <= 39 and _ascii_handle(h)):
            seen.add(h)
            uniq.append(h)
    return uniq[:limit]


# Words that appear in almost every context string and identify nobody. Building
# "jason-secondary" or "amarsh-university" wastes probes on generic vocabulary.
_CONTEXT_STOPWORDS = {
    "the", "and", "for", "with", "from", "school", "secondary", "primary",
    "university", "college", "student", "graduate", "company", "limited",
    "ltd", "inc", "corp", "group", "team", "department", "hong", "kong",
    "national", "international", "institute", "center", "centre",
}
def contextual_handles(name: str, context: str = "", aliases: list | None = None,
                       limit: int = 24) -> list:
    """Handles that splice the name with the person's FIELD or affiliation.

    This is the "AMarsh-Sec" shape, and it is the gap a plain permuter can
    never close: no enumerator guesses `-Security` from the two words "Alex
    Marsh". But it is entirely guessable from "Alex Marsh, AI security" — the
    suffix is not random, it is the person's domain, and the operator usually
    supplied exactly that as the disambiguating context.

    So context stops being only a *filter* for scoring candidates and becomes a
    *generator* of them. Output still goes through `confirm_handle` like
    everything else; this widens the candidate net, it never widens what counts
    as proof.
    """
    base = handle_permutations(name, limit=8)
    base += [h for a in (aliases or [])[:1] for h in handle_permutations(a, 4)]
    tokens = [t for t in _norm(context).split()
              if len(t) > 1 and t not in _CONTEXT_STOPWORDS]
    # Initialisms of the affiliation ("Ko Lui Secondary School" -> "klss") are
    # how institutions are actually written in a handle.
    ctx_words = list(dict.fromkeys(tokens))[:3]
    if len(tokens) > 1:
        ctx_words.append("".join(t[0] for t in _norm(context).split() if t))
    # Suffixes come ONLY from the person's actual context (their field /
    # affiliation), so this adapts to anyone — 'amarsh-sec' for an AI-security
    # person, 'chan-parish' for a clergy member, 'wong-atelier' for an artist.
    # The old fixed tech list ('dev/sec/ai/eng') assumed every target was a
    # techie and produced pure noise for everyone else.
    ctx_words = list(dict.fromkeys(ctx_words))

    # Loop order IS the feature here, because `limit` truncates the tail.
    # Separator outermost (hyphen first — the dominant real-world form), then
    # context word, then base form. Every (base, word) pair therefore gets a
    # hyphenated candidate before ANY pair gets a second separator.
    #
    # Both other orderings fail the motivating case. Base-major spends the whole
    # budget on "alexmarsh" and never reaches "amarsh"; separator-in-the-middle
    # spends it on "ai" and never reaches "security". Either way `amarsh-sec`
    # — the exact shape this function exists to produce — falls off the end.
    out: list = []
    seen = set()
    for sep in ("-", "", "_", "."):
        for w in ctx_words:
            for h in base:
                if not w or w == h:
                    continue
                cand = f"{h}{sep}{w}"
                if (2 <= len(cand) <= 39 and cand not in seen
                        and _ascii_handle(cand)):
                    seen.add(cand)
                    out.append(cand)
    return out[:limit]


def _declared_name(handle: str, fetcher) -> list:
    """[(platform, declared_name, url)] for every platform that names this handle."""
    found = []
    for platform, api, fields, page in _NAME_SOURCES:
        actor = handle
        if platform == "Bluesky" and "." not in handle:
            actor = f"{handle}.bsky.social"
        data = fetcher.get_json(api.format(u=actor), headers=_UA)
        if not isinstance(data, dict) or data.get("__status__") == 404:
            continue
        # An account must exist AND declare a name; a nameless account is a
        # non-answer here, never a partial match.
        for f in fields:
            val = (data.get(f) or "").strip()
            if val:
                found.append((platform, val, page.format(u=actor)))
                break
    return found


def confirm_handle(handle: str, name: str, fetcher,
                   aliases: list | None = None) -> dict:
    """Does this handle's own metadata name this person?

    Returns {'handle', 'verdict', 'links'} where verdict is:
      confirmed   - an account exists and PUBLICLY DECLARES the target's name
      unconfirmed - an account exists but names someone else / nobody
      absent      - no account with this handle on the checked platforms
    """
    wanted = [set(_norm(n).split()) for n in ([name] + list(aliases or []))
              if _norm(n)]
    declared = _declared_name(handle, fetcher)
    if not declared:
        return {"handle": handle, "verdict": "absent", "links": []}

    hits = []
    for platform, dname, url in declared:
        dn_tokens = set(_norm(dname).split())
        # EVERY token of the target name must appear in the declared name.
        #
        # Substring matching in either direction is not good enough and quietly
        # manufactures false links: a profile declaring just "Linus" was matched
        # against "Linus Torvalds" because one string contains the other, so a
        # stranger who shares a FIRST NAME was reported as a confirmed identity
        # link. That is precisely the misattribution this module exists to
        # prevent, so the bar is full token coverage.
        #
        # Superset declarations still pass ("Dr Alex Marsh" covers "Alex Marsh"),
        # and token-set comparison makes order irrelevant, so "Jing Yi Wong"
        # confirms "Wong Jing Yi". A partial declaration never does.
        if any(toks and toks <= dn_tokens for toks in wanted):
            hits.append({"platform": platform, "declared": dname, "url": url})
    if hits:
        return {"handle": handle, "verdict": "confirmed", "links": hits}
    return {"handle": handle, "verdict": "unconfirmed",
            "links": [{"platform": p, "declared": d, "url": u}
                      for p, d, u in declared]}


# Handles harvested from result URLs. Ordered by how much a hit is worth:
# an OBSERVED handle already co-occurred with the target somewhere on the web,
# which is a real signal; a GENERATED one is a guess until confirmed.
_URL_HANDLE = (
    re.compile(r"github\.com/([A-Za-z0-9][A-Za-z0-9\-]{0,38})", re.I),
    re.compile(r"bsky\.app/profile/([A-Za-z0-9._\-]+)", re.I),
    re.compile(r"mastodon\.social/@([A-Za-z0-9_]+)", re.I),
    re.compile(r"(?:twitter|x)\.com/([A-Za-z0-9_]{2,15})", re.I),
    re.compile(r"instagram\.com/([A-Za-z0-9_.]{2,30})", re.I),
    re.compile(r"linkedin\.com/in/([A-Za-z0-9\-_%]+)", re.I),
)
# Path segments that are site furniture, not people.
_NOT_HANDLES = {
    "about", "login", "signup", "search", "explore", "settings", "help",
    "home", "features", "pricing", "orgs", "topics", "collections", "sponsors",
    "notifications", "new", "share", "privacy", "terms", "legal", "blog",
    "posts", "events", "jobs", "company", "school", "feed", "p", "reel",
    "enterprise", "sponsors", "marketplace", "trending", "readme",
}
# Locale segments: `linkedin.com/en/...`, `instagram.com/tw/...`. Observed
# harvesting "en" as a handle and spending a probe on github.com/en (a real
# account, belonging to Julian Sun) — confirmation rejected it correctly, but
# the probe was wasted and the row was noise.
_NOT_HANDLES |= {
    "en", "de", "fr", "es", "it", "pt", "nl", "ru", "ja", "ko", "zh", "tw",
    "hk", "cn", "br", "in", "uk", "us", "id", "th", "vi", "tr", "pl", "sv",
}


def handles_from_results(results, cap: int = 12) -> list:
    """Handles that actually appeared in search results, most-seen first.

    These are the ones that pay off. A handle the web already prints next to
    the target's name has passed a filter no generated permutation has.
    """
    counts: dict = {}
    for r in results or []:
        blob = f"{getattr(r, 'url', '')} {getattr(r, 'snippet', '')}"
        for pat in _URL_HANDLE:
            for m in pat.finditer(blob):
                h = m.group(1).strip("._-").lower()
                if h and h not in _NOT_HANDLES and not h.isdigit():
                    counts[h] = counts.get(h, 0) + 1
    return [h for h, _ in sorted(counts.items(), key=lambda kv: -kv[1])][:cap]


def link_name_to_handles(name: str, handles: list, fetcher,
                         aliases: list | None = None,
                         cap: int = 20) -> SourceRun:
    """Confirm a set of candidate handles against a real name.

    `handles` should lead with handles actually observed in search results
    (extracted from profile URLs) — those are the ones that pay off. Generated
    permutations may follow as lower-yield extras.
    """
    if not getattr(fetcher, "live", False):
        return SourceRun("handle_link", "Name↔handle confirmation", "public",
                         "planned",
                         detail=f"{len(handles[:cap])} handle(s) ready (--live)")
    results, confirmed, unconfirmed = [], 0, 0
    seen: set = set()
    for h in handles[:cap]:
        h = (h or "").lstrip("@").strip()
        if not h or h.lower() in seen:
            continue
        seen.add(h.lower())
        out = confirm_handle(h, name, fetcher, aliases)
        if out["verdict"] == "confirmed":
            confirmed += 1
            for link in out["links"]:
                results.append(SearchResult(
                    "handle_link", "public",
                    title=f"{link['platform']}: @{h} publicly declares "
                          f"\"{link['declared']}\"",
                    url=link["url"],
                    snippet=("CONFIRMED link — this account states the target's "
                             "name in its own public profile. That declaration "
                             "is what connects the handle to the person; remove "
                             "it and the link breaks."),
                    meta={"handle": h, "verdict": "confirmed",
                          "platform": link["platform"]}))
        elif out["verdict"] == "unconfirmed":
            unconfirmed += 1
            for link in out["links"][:1]:
                results.append(SearchResult(
                    "handle_link", "public",
                    title=f"{link['platform']}: @{h} exists but names "
                          f"\"{link['declared']}\"",
                    url=link["url"],
                    snippet=("NOT LINKED — an account with this handle exists, "
                             "but its profile does not name the target. Treat "
                             "as a different person unless other evidence ties "
                             "them together."),
                    meta={"handle": h, "verdict": "unconfirmed",
                          "platform": link["platform"]}))
    detail = (f"{confirmed} confirmed link(s), {unconfirmed} same-handle "
              f"account(s) belonging to someone else, across "
              f"{len(seen)} handle(s) checked. A link is only reported when the "
              f"account itself declares the name.")
    return SourceRun("handle_link", "Name↔handle confirmation", "public",
                     "ok" if confirmed else ("empty" if not results else "ok"),
                     detail=detail, results=results)


def resolve_handles(name: str, context: str, results, fetcher,
                    aliases: list | None = None, cap: int = 20) -> SourceRun:
    """Full name->handle resolution: observe, generate, then CONFIRM.

    Ordering is the design. Handles seen in real results go first because they
    have already co-occurred with the target; context-spliced guesses
    ("amarsh-sec") come next because the operator's context makes them
    plausible; blind permutations come last and usually get truncated away.
    Confirmation is identical for all three — where a candidate came from
    changes only its priority, never its burden of proof.
    """
    observed = handles_from_results(results)
    ctx = contextual_handles(name, context, aliases, limit=16)
    plain = handle_permutations(name, limit=8)
    ordered, seen = [], set()
    for h in observed + ctx + plain:
        if h.lower() not in seen:
            seen.add(h.lower())
            ordered.append(h)
    run = link_name_to_handles(name, ordered, fetcher, aliases, cap=cap)
    run.detail = (f"{len(observed)} handle(s) observed in results, "
                  f"{len(ctx)} context-derived, {len(plain)} generated. "
                  + run.detail)
    return run
