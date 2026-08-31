"""Entity extraction and link-graph correlation.

Given the raw text of every result (plus the input-folder context), we pull out
identifiers, deduplicate them into a canonical entity set, and connect the
target to everything that co-occurs with it. The result is a small graph that
the HTML report renders as an interactive node-link diagram -- the "visual
tracking" surface of Black Noir.
"""

from __future__ import annotations

import os
import re

from .models import Edge, Entity, Investigation, SearchResult

# --- extraction patterns ----------------------------------------------------

PATTERNS: dict[str, re.Pattern] = {
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "onion": re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.I),
    "btc": re.compile(r"\b(?:bc1[a-z0-9]{20,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    # The leading '(' is part of the match, not skipped: starting at the first
    # digit turned "(852) 5550 0102" into the value "852) 5550 0102" — a node
    # carrying an unbalanced paren, and a second, separate node from the same
    # line as the bare "5550 0102".
    "phone": re.compile(r"(?<![\d(])\(?\+?\d[\d\s().-]{7,}\d(?!\d)"),
    "domain": re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        # gTLDs + the common ccTLDs. The old list omitted every country code —
        # so 'sbc.edu.example' failed to type as a domain and was mis-routed as a
        # username. ccTLDs are what most non-US targets actually use.
        r"(?:com|net|org|io|co|info|biz|ru|onion|me|dev|xyz|to|cc|ai|app|tech|"
        r"edu|gov|mil|int|hk|uk|jp|cn|tw|sg|au|ca|de|fr|nl|in|us|eu|nz|kr|it|"
        r"es|br|mx|ch|se|no|fi|dk|be|at|ie|pt|pl|id|my|ph|th|vn|ae|za|ke|ng)\b",
        re.I,
    ),
    "handle": re.compile(r"(?<![\w@])@[A-Za-z0-9_]{3,32}\b"),
}

# domains that are search infrastructure, not findings
NOISE_DOMAINS = {
    "duckduckgo.com", "bing.com", "google.com", "ahmia.fi", "haystak.io",
    "lyzem.com", "t.me", "haveibeenpwned.com", "dehashed.com",
    "onionlandsearchengine.net", "onionsearchengine.com", "w3.org",
    "schema.org", "gstatic.com",
    # reverse-image engines themselves are infrastructure, not findings
    "saucenao.com", "iqdb.org", "lens.google.com", "images.google.com",
    "yandex.com", "tineye.com",
    # giant sites that show up as search-result chrome, not real findings
    "youtube.com", "youtubekids.com", "amazon.com", "amazon.co", "baidu.com",
    "zhihu.com", "shein.com", "play.google.com", "apple.com", "dwell.com",
    "lespac.com", "arcanum.com", "wikipedia.org", "reddit.com",
    "stackoverflow.com", "facebook.com", "instagram.com", "torproject.org",
    # platform + reference + knowledge-base hosts: a person never *owns* these,
    # so the bare domain is search chrome, not a finding (a real profile is
    # still captured as its own result/handle, just not as a domain node)
    "linkedin.com", "lnkd.in", "wikidata.org", "wikimedia.org", "github.com",
    "archive.org", "web.archive.org", "rocketreach.co", "zoominfo.com",
    # cert-transparency / CDN infrastructure that surfaces via crt.sh SANs
    "lnkdns.net", "cloudflare.net", "cloudfront.net", "akamai.net",
    "akamaiedge.net", "fastly.net",
}


def classify_target(target: str) -> str:
    t = target.strip()
    if PATTERNS["email"].fullmatch(t):
        return "email"
    if PATTERNS["onion"].search(t):
        return "onion"
    if t.startswith("@") or PATTERNS["handle"].fullmatch(t):
        return "username"
    if PATTERNS["ip"].fullmatch(t):
        return "ip"
    if re.fullmatch(r"\+?\d[\d\s().-]{6,}\d", t):
        return "phone"
    if PATTERNS["domain"].fullmatch(t):
        return "domain"
    if " " in t:
        return "name"
    return "username"


# The vocabulary the rest of the pipeline can actually route on. Every module
# that branches on a target type (source selection, enrichment, pivots, the
# person gate) tests against members of this set, so a type outside it silently
# disables all of them: the run still completes, still reports, and simply
# never fires the modules keyed to what the target IS.
#
# This is not hypothetical. `parse_target` let the model answer "other" for
# "+852 5550 0101", that string was taken verbatim, and the phone path —
# numbering-plan analysis, phone pivots, Numverify — declined a target that
# `classify_target` types as "phone" without hesitation. The report said
# `Target type: other` and carried no phone section at all.
KNOWN_TARGET_TYPES = frozenset({
    "name", "person", "username", "handle", "email", "domain", "company",
    "ip", "phone", "btc", "onion",
})


def resolve_target_type(declared: str, subject: str) -> str:
    """Accept a model-declared target type only if the pipeline can route it.

    The deterministic classifier is the floor, not the fallback of last resort:
    it reads the subject string itself, so where the two disagree about a
    machine-readable identifier the regex is the one holding evidence.
    """
    d = (declared or "").strip().lower()
    if d in KNOWN_TARGET_TYPES:
        return d
    return classify_target(subject)


def _is_noise_host(url: str) -> bool:
    """True for links pointing back at the search infrastructure itself."""
    from urllib.parse import urlparse
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False
    return any(host == n or host.endswith("." + n) for n in NOISE_DOMAINS)


# Unicode-aware (`[^\W_]` is word-chars minus underscore). An ASCII-only
# `[a-z0-9]+` tokenised "高蕾中學" to NOTHING, so a CJK school/employer supplied
# as disambiguating context contributed zero tokens and could never corroborate
# anything — on precisely the targets where the Chinese name is the strongest
# discriminator and the romanisation is shared by hundreds of strangers.
_TOKEN = re.compile(r"[^\W_]+", re.UNICODE)

# CJK has no spaces, so a whole name/term arrives as one long token. Those are
# distinctive enough to match as substrings; short ASCII tokens are not.
_CJK = re.compile(r"[぀-ヿ㐀-䶿一-鿿가-힯]")


def _significant_tokens(text: str) -> list[str]:
    """Lowercase word tokens of 2+ chars, used for target/result matching."""
    return [t for t in _TOKEN.findall((text or "").lower()) if len(t) >= 2]


# How far apart two parts of ONE person's name may sit and still be that name.
# A full name spans a few dozen characters even with a title or middle initial.
NAME_WINDOW = int(os.environ.get("BLACKNOIR_NAME_WINDOW", "60"))

# Context words too common in their own region to discriminate anything. A
# Hong Kong target's context contains "hong kong", and so does every Hong Kong
# page ever written — letting those corroborate a name match means the context
# filter approves the entire local internet. The specific tokens (the school's
# actual name, a phone number) still do the work.
_GENERIC_CONTEXT = {
    "hong", "kong", "china", "chinese", "school", "schools", "secondary",
    "primary", "college", "university", "student", "students", "district",
    "city", "town", "road", "street", "centre", "center",
    "limited", "ltd", "inc", "company", "group", "international", "national",
    # English function words. A context phrased as prose ("a student from X in
    # hong kong") tokenises to include these, and they corroborate nothing —
    # "from" and "in" appear on every page ever written, so leaving them in
    # means the context filter is satisfied by any document at all.
    "the", "and", "a", "an", "of", "in", "at", "on", "for", "with", "from",
    "to", "by", "is", "was", "who", "whose", "that", "this", "his", "her",
    "he", "she", "they", "it", "as", "or", "but", "be", "been", "are",
}


def _token_spans(token: str, hay: str) -> list[int]:
    """Start offsets of every word-boundary occurrence of `token`."""
    if not token:
        return []
    if _CJK.search(token):
        return [m.start() for m in re.finditer(re.escape(token), hay)]
    return [m.start() for m in re.finditer(
        rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", hay)]


def _co_occur(tokens: list[str], hay: str, window: int = NAME_WINDOW) -> bool:
    """Do all `tokens` appear close enough together to be one name?

    Presence anywhere in the document is not evidence of a name. A 20,000-char
    inter-school competition page carrying 231 distinct people contains "Wong"
    fourteen times and "Yi" five times — in fourteen and five OTHER people's
    names. Matching "Wong Jing Yi" against it because both syllables exist
    somewhere on the page is how a stranger's prize listing becomes evidence
    about a specific teenager.

    So the tokens must fall inside one `window`-character span. Cheap version of
    what a real search engine calls proximity ranking, and it is the difference
    between "these letters are on the page" and "this name is on the page".
    """
    spans = [_token_spans(t, hay) for t in tokens]
    if any(not s for s in spans):
        return False
    # Anchor on the rarest token; every other token must have an occurrence
    # within the window of one of its positions.
    anchor = min(spans, key=len)
    others = [s for s in spans if s is not anchor]
    for pos in anchor:
        if all(any(abs(p - pos) <= window for p in s) for s in others):
            return True
    return False


def _token_present(token: str, hay: str) -> bool:
    """Is `token` in `hay` as a WORD, not as an incidental substring?

    Raw `in` matching is unsafe for short romanised syllables: "yi" is inside
    "Yiu", "Ying" and "Yip", all common in Hong Kong text, so a page about a
    different person or a district would satisfy a name check.

    Defined in terms of `_token_spans` on purpose. The boundary rule used to be
    written out twice — once here, once there — and duplicated rules drift:
    a mutation test that broke this copy still passed, because the other copy
    silently held the line. One definition means one place to get it right, and
    one place a test can prove is load-bearing.
    """
    return bool(_token_spans(token, hay))


def is_about_target(text: str, target: str, context: str = "",
                    aliases: list[str] | None = None) -> bool:
    """Does this result plausibly concern the target?

    A search engine returns whatever it likes — for a common name that is
    mostly other people, and for a broken engine it is unrelated pages
    entirely. Linking every one of those to the target is how a graph ends up
    asserting that a person is connected to a deli, a Telegram channel and a
    Wayback timestamp. Results that fail this test still appear under their
    source in the report; they just do not get to invent graph edges.
    """
    if not target:
        return False
    hay = (text or "").lower()
    if target.lower() in hay:
        return True
    # An alternate name for the same person is as good as the primary one, and
    # is often stronger: a native-script name ("林永傑") is far more unique than
    # its romanization, so a page carrying it is almost certainly on-target.
    for alt in (aliases or []):
        alt = (alt or "").strip().lower()
        if len(alt) >= 2 and alt in hay:
            return True
    name_tokens = _significant_tokens(target)
    if not name_tokens:
        return False
    present = [t for t in name_tokens if _token_present(t, hay)]
    # Every part of the name present (order-independent: "Marsh, Alex") AND
    # close enough together to be one name rather than fragments of several.
    if len(present) == len(name_tokens):
        return _co_occur(name_tokens, hay)
    # A partial match must include the SURNAME (the distinguishing token), not
    # merely a shared first name. Without this, "Alex Bell" and "Alex
    # Clinton" both match a search for "Alex Marsh" as soon as the AI-security
    # context appears in the same snippet.
    #
    # The trailing token is the surname for a Western name, so it alone (plus
    # agreeing context) qualifies: "Marsh presenting AI security research".
    last_ok = _token_present(name_tokens[-1], hay)
    # Romanised CJK names invert that — "Wong Jing Yi" carries the family name
    # in position 0 and splits the given name across the remaining tokens, so
    # requiring the LAST token meant demanding "yi", the least distinctive
    # syllable in the name, and a page reading "Wong Jing ... 高蕾中學" was
    # rejected outright.
    #
    # A leading token cannot qualify alone, though — "Alex Bell" shares
    # "Alex" with "Alex Marsh" and must stay out. So the lead path needs a
    # second token as well, and only applies to 3+ token names, which is the
    # shape that has this problem. Two-token Western names are unaffected and
    # the shared-first-name guard is exactly as strict as before.
    lead_ok = (len(name_tokens) >= 3
               and _token_present(name_tokens[0], hay)
               and len(present) >= 2
               and _co_occur(present, hay))
    if not (last_ok or lead_ok):
        return False
    # surname present but not the full name: accept only when the
    # disambiguating context also agrees.
    if context:
        ctx_tokens = [c for c in _significant_tokens(context)
                      if c not in _GENERIC_CONTEXT]
        # The name fragment and the context must corroborate EACH OTHER, which
        # means sitting together. Scattered across a long page they do not:
        # a competition listing hundreds of Hong Kong students contains the
        # surname and the words "hong kong" many times over without ever being
        # about this person. Widened past NAME_WINDOW because "<name> … <school>"
        # is a looser pairing than the parts of a single name.
        matched = [t for t in name_tokens if _token_present(t, hay)]
        return any(_co_occur([m, c], hay, window=NAME_WINDOW * 3)
                   for m in matched for c in ctx_tokens)
    return False


def _iter_text(results: list[SearchResult], input_context: dict,
               target: str = "", context: str = "",
               aliases: list[str] | None = None):
    """Yield (source, text, relevant, body) for every minable piece of text.

    `body` is the human-written part (title + snippet) with the URL excluded.
    Kinds whose pattern is satisfied by ordinary URL punctuation are mined from
    `body` only — see PHONE_FREE_OF_URLS in `correlate`.
    """
    for r in results:
        # Mine title+snippet always; include the URL only when it is a genuine
        # finding, never the engine's own query URL (which would inject the
        # engine host and %40-style encoding artifacts as fake entities).
        body = f"{r.title} {r.snippet}"
        text = body
        if r.url and (r.is_onion or not _is_noise_host(r.url)):
            text += f" {r.url}"
        # Enrichment/sweep results are target-derived by construction: they were
        # fetched *because* of a confirmed entity, so they are not name-matched.
        derived = r.source in ("enrich_domain", "enrich_ip", "enrich_btc",
                               "enrich_username", "username_sweep", "hibp",
                               "dehashed", "intelx")
        yield r.source, text, (derived
                               or is_about_target(text, target, context, aliases)), body
    for note in input_context.get("notes", []):
        yield "input", note, True, note
    for img in input_context.get("images", []):
        analysis = img.get("analysis", "")
        yield "input", analysis, True, analysis


# Kinds mined from title+snippet only, never from the URL. A URL path is dense
# in digits, dashes and dots, which is exactly the shape of a loose phone
# pattern: `.../c186330-40010797.html` (a people.com.cn article id) satisfied
# every length and formatting check and became a "phone" node wired to the
# target. Nothing is lost by the exclusion — a real number published on a page
# is written in the page, not encoded in its path.
_BODY_ONLY_KINDS = {"phone"}


def _merge_phone(value: str, entities: dict, phone_index: dict):
    """Collapse the same line written two ways into the more complete node.

    A directory entry prints "(852) 5550 0102" in one field and "5550 0102" in
    another; a naive graph shows two unrelated numbers. When one number's
    digits are a suffix of another's, they are the same line with and without
    its country/area prefix, and the longer form is the one worth keeping.
    """
    digits = re.sub(r"\D", "", value)
    if len(digits) < 7:
        return None
    for other, key in list(phone_index.items()):
        if other == digits:
            continue
        existing = entities.get(key)
        if existing is None:
            continue
        if digits.endswith(other):
            # New value carries the prefix the stored one lacked: promote it.
            existing.value = value
            existing.weight += 1
            del phone_index[other]
            entities.pop(key, None)
            entities[existing.key()] = existing
            phone_index[digits] = existing.key()
            return existing
        if other.endswith(digits):
            # Stored value is already the fuller form.
            existing.weight += 1
            return existing
    return None


def correlate(inv: Investigation, extra_noise: set | None = None) -> None:
    """Populate inv.entities and inv.edges from inv.runs + input context.

    `extra_noise` is an optional per-run set of domains the AI judged to be
    infrastructure/platform noise (not the target's own). It extends the static
    NOISE_DOMAINS baseline for this investigation only — the list is the always-on
    floor; the model decides the rest.
    """
    entities: dict[str, Entity] = {}
    noise_extra = {str(n).strip().lower().strip(".")
                   for n in (extra_noise or ()) if n}
    # digits -> entity key, so the same line written two ways collapses to one
    # node instead of two (see _merge_phone).
    phone_index: dict[str, str] = {}

    # seed with the target itself
    target = Entity(inv.target, inv.target_type, "target", weight=6)
    entities[target.key()] = target

    def add(value: str, kind: str, source: str) -> Entity | None:
        # Brackets are punctuation to strip off a domain or a handle, but they
        # are part of a phone number's own notation. Stripping them here turned
        # "(852) 5550 0102" into the unbalanced "852) 5550 0102" before the
        # phone checks below ever saw it — which is how one line became two
        # nodes, one of them malformed.
        value = value.strip().strip(".,: " if kind == "phone" else ".,)( ")
        if not value or len(value) > 120:
            return None
        if kind == "domain":
            low = value.lower()
            if any(low == n or low.endswith("." + n) for n in NOISE_DOMAINS):
                return None
            if any(low == n or low.endswith("." + n) for n in noise_extra):
                return None
        if kind == "ip" and value.count(".") != 3:
            return None
        if kind == "phone":
            digits = re.sub(r"\D", "", value)
            # reject coordinates/decimals, wrong length, and repeated-digit junk
            if ("." in value or not (7 <= len(digits) <= 15)
                    or len(set(digits)) <= 2):
                return None
            v = value.strip()
            # A real phone in a snippet is *formatted*: a leading '+', a space or
            # parenthesis between groups, or a dash between digits. A bare,
            # unbroken digit run is almost always an identifier, not a phone — a
            # Wikidata Q-id (139770117), a profile-URL slug (..._424086952), an
            # epoch or a Wayback timestamp. Requiring formatting drops those
            # false 'phone' nodes instead of asserting a stranger's "number".
            # Trade-off: a genuinely un-punctuated number (e.g. "55500103") is
            # skipped here — but the same number, formatted, still forms the node
            # wherever it also appears spaced/'+'-prefixed.
            has_format = (v.startswith("+") or bool(re.search(r"[ ()]", v))
                          or bool(re.search(r"\d-\d", v)))
            if not has_format:
                return None
            # reject year ranges like "2016 - 2018" / "2016-2018": two plausible
            # years joined by a dash otherwise read as an 8-digit 'phone'.
            if re.fullmatch(r"(?:19|20)\d{2}\s*[-–]\s*(?:19|20)\d{2}", v):
                return None
            # Unbalanced brackets mean the match started or ended mid-token, so
            # the value is a fragment of something else rather than a number.
            if v.count("(") != v.count(")"):
                return None
            value = v

        ent = Entity(value, kind, source)
        k = ent.key()
        if k in entities:
            entities[k].weight += 1
            return entities[k]
        if kind == "phone":
            merged = _merge_phone(value, entities, phone_index)
            if merged is not None:
                return merged
            phone_index[re.sub(r"\D", "", value)] = k
        entities[k] = ent
        return ent

    skipped = 0
    for source, text, relevant, body in _iter_text(
            inv.all_results, inv.input_context,
            inv.target, getattr(inv, "context", ""),
            getattr(inv, "aliases", None)):
        if not relevant:
            # off-target result: its identifiers belong to somebody else
            skipped += 1
            continue
        for kind, pat in PATTERNS.items():
            haystack = body if kind in _BODY_ONLY_KINDS else text
            for m in pat.findall(haystack):
                val = m if isinstance(m, str) else m[0]
                ent = add(val, kind, source)
                if ent and ent.key() != target.key():
                    inv.edges.append(
                        Edge(target.key(), ent.key(), "co-occurs", source)
                    )
    inv.correlation_skipped = skipped

    # Structured identifiers read from input images by the vision model are
    # trusted directly (no regex needed) and linked to the target as strong
    # image-derived pivots.
    _VISION_KIND = {
        "names": "name", "usernames": "username", "handles": "handle",
        "domains": "domain", "emails": "email", "watermarks": "domain",
        "platforms": "handle",
    }
    for img in inv.input_context.get("images", []):
        for field, values in (img.get("extracted") or {}).items():
            kind = _VISION_KIND.get(field)
            if not kind:
                continue
            for val in values:
                ent = add(val, kind, "image")
                if ent and ent.key() != target.key():
                    ent.weight += 1  # image-sourced marks are high value
                    inv.edges.append(
                        Edge(target.key(), ent.key(), "from-image", "image"))

    # de-dup edges
    seen = set()
    unique: list[Edge] = []
    for e in inv.edges:
        sig = (e.src, e.dst, e.source)
        if sig not in seen:
            seen.add(sig)
            unique.append(e)
    inv.edges = unique
    inv.entities = list(entities.values())
