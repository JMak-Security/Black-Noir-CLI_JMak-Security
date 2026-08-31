"""Natural-language target parsing.

Turns a free-form instruction ("This is Jensen Huang, search every secret
detail about him") into a structured search intent:

    {subject, subject_type, depth, is_question, context}

so the rest of the pipeline searches the *entity* ("Jensen Huang") instead of
the literal sentence. The Agent uses an LLM for this when available; this module
is the deterministic fallback and the shared vocabulary.

`context` is the qualifier that disambiguates a common name — in
'"Alex Marsh" who is from AI Security Industry' the subject is "Alex Marsh" and
the context is "AI Security Industry". Dropping it is what turns a findable
person into 100 namesakes, so it is extracted here and consumed by the query
builder, not merely recorded in the report.
"""

from __future__ import annotations

import re

from .entities import classify_target

# command / filler phrases to strip, longest first
_STRIP = [
    "search every secret details about", "search every secret detail about",
    "search every detail about", "search all details about",
    "search everything about", "find everything about",
    "tell me everything about", "dig up everything about",
    "do a deep dive on", "find out everything about", "find out about",
    "deep dive on", "look into", "investigate", "research on", "research",
    "osint on", "search for", "look up", "lookup", "find me", "find",
    "search", "identify this person", "identify",
    "who is this person", "who is this", "who is", "what is this", "whose is this",
]

_FILLER = re.compile(
    r"\b(him|her|them|his|hers|their|theirs|this person|this|that|about|please|"
    r"everything|every|secret|secrets|detail|details|the|all)\b",
    re.I)

# Words that are filler as pronouns but meaningful as proper nouns, so they are
# only stripped in lowercase: "who is this man" loses 'man', "Isle of Man" and
# "Person of Interest" keep theirs.
_FILLER_PERSONWORDS = re.compile(r"\b(guy|man|woman|person)\b")

_DEEP_HINTS = ("every", "everything", "all detail", "all the", "deep",
               "comprehensive", "secret", "thorough", "exhaustive", "full")

# A quoted segment: the first is the subject, the rest are aliases for it.
_QUOTED = re.compile(r'["“]([^"”]{2,80})["”]')

# Phrases that introduce a disambiguating qualifier after the subject.
# Ordered longest-first within each family so "working at" wins over "at" and
# the connective is not left stranded on the end of the subject.
_CONTEXT_LEAD = re.compile(
    r"\b(?:"
    r"who\s+(?:is|was|works?|worked|working)\s+(?:from|at|in|for|with)|"
    r"who\s+(?:is|was)|"
    r"work(?:s|ed|ing)?\s+(?:at|for|in|on)|"
    r"employed\s+(?:at|by)|"
    r"based\s+(?:in|at)|"
    r"from\s+the|from|"
    r"at\s+the|at|"
    r"in\s+the|in|"
    r"of\s+the|of"
    r")\b\s+(.+)$", re.I)

# A bare connective ("of", "in") only splits a subject when what precedes it
# already looks like a full name. Without this, "University of California"
# would be cut down to subject "University", context "California".
_MIN_SUBJECT_WORDS_BEFORE_LEAD = 2

# Words that mark the prefix as an ORGANISATION whose own name contains a
# connective ("Massachusetts Institute of Technology", "Bank of America").
# Splitting on their connective destroys the entity, so it is never done.
_ORG_WORDS = {
    "university", "institute", "college", "school", "academy", "bank",
    "ministry", "department", "bureau", "board", "council", "chamber",
    "isle", "city", "state", "republic", "kingdom", "church", "museum",
    "hospital", "association", "society", "federation", "union", "house",
    "court", "office", "centre", "center", "foundation", "trust", "company",
    "corporation", "group", "agency", "commission", "authority", "league",
    "order", "bay", "port", "lake", "cape", "fort", "mount", "district",
}


def _looks_like_org(prefix: str) -> bool:
    """True when the text before a connective is an organisation/place name."""
    return any(w.strip(".,").lower() in _ORG_WORDS for w in prefix.split())

# generic words that carry no disambiguating power on their own
_WEAK_CONTEXT = {"the", "a", "an", "company", "industry", "person", "guy",
                 "man", "woman", "someone", "somebody", "him", "her", "them"}

# Abbreviations whose trailing period is part of the word, not a sentence end.
# A qualifier is very often an institution or address containing one
# ("St. Brendon College", "Mt. Sinai Hospital", "Acme Inc."), so treating
# their period as a clause boundary truncates the qualifier to a stub.
_ABBREV = {
    "st", "mt", "ft", "pt", "mr", "mrs", "ms", "dr", "prof", "rev", "hon",
    "sr", "jr", "rd", "ave", "blvd", "ln", "dept", "univ", "inst", "assn",
    "inc", "ltd", "llc", "plc", "co", "corp", "bros", "no", "vs", "etc",
    "approx", "est", "fig", "vol", "ed",
}

# Boundaries that can end the qualifier and start a trailing command clause.
# An opening bracket ends it too: the chat layer appends its own parenthetical
# ("(comprehensive deep search, every public detail)"), and without this the
# qualifier absorbs that fragment and every query carries it.
_CLAUSE_CUT = re.compile(
    r"[,;(\[]|\.|\band\s+(?:search|find|tell|dig|look)\b", re.I)


def _cut_trailing_clause(text: str) -> str:
    """Drop a trailing command clause without tripping over abbreviations.

    Splitting naively on '.' turns "St. Brendon College in
    Hong Kong" into "St", which then fails the length guard in
    `extract_context` and silently discards the whole qualifier — leaving the
    subject to be searched as a bare, ambiguous name. A period only ends the
    qualifier when it is neither an abbreviation nor an initial, and is
    actually followed by whitespace (so domains and decimals stay intact).
    """
    for m in _CLAUSE_CUT.finditer(text):
        if m.group(0) == ".":
            word = re.search(r"([A-Za-z]+)$", text[:m.start()])
            token = word.group(1).lower() if word else ""
            if token in _ABBREV or len(token) == 1:   # "St." / initial "J."
                continue
            tail = text[m.end():]
            if tail and not tail[0].isspace():        # "example.com", "3.5"
                continue
        return text[:m.start()]
    return text


def extract_context(raw: str, subject: str) -> str:
    """Pull the qualifier that distinguishes this subject from its namesakes.

    Returns "" when the instruction carries no usable qualifier. The result is
    appended to search queries, so it must be search-engine-friendly text
    (an industry, employer, location or role) rather than a full sentence.
    """
    s = (raw or "").strip()
    if not s or not subject:
        return ""
    # look at whatever follows the subject in the original instruction
    idx = s.lower().find(subject.lower())
    tail = s[idx + len(subject):] if idx >= 0 else s
    tail = tail.strip(" ,.:;-\"'")
    if not tail:
        return ""
    m = _CONTEXT_LEAD.search(tail)
    # don't harvest context out of an organisation's own name
    if m and _looks_like_org(subject):
        return ""
    cand = (m.group(1) if m else tail).strip(" ,.:;-\"'")
    # drop trailing command clauses ("... , search everything about him")
    cand = _cut_trailing_clause(cand)
    for p in _STRIP:                       # strip embedded command phrases
        cand = re.sub(re.escape(p), " ", cand, flags=re.I)
    cand = re.sub(r"\s+", " ", cand).strip(" ,.:;-\"'")
    words = [w for w in cand.split() if w.lower() not in _WEAK_CONTEXT]
    if not words or len(cand) < 3 or len(cand) > 120:
        return ""
    return cand


def extract_aliases(raw: str, subject: str) -> list[str]:
    """Every *other* name the instruction gives for the same subject.

    An instruction routinely carries a person's name in more than one form —
    a romanization, a legal name, a native-script name ('"Kenmen Cho" whose
    full name is "林永傑" or "Lam Wing Kit"'). Only the first quoted segment
    becomes the subject; the rest used to be discarded, so the one query form
    most likely to be unique (the native-script name) was never searched and
    genuine hits were scored as off-target. They are returned here so the
    query builder and the relevance filter can both use them.
    """
    s = (raw or "").strip()
    if not s:
        return []
    seen = {(subject or "").strip().lower()}
    out: list[str] = []
    for q in _QUOTED.findall(s):
        cand = q.strip(" ,.:;-\"'")
        low = cand.lower()
        if not cand or low in seen or len(cand) > 80:
            continue
        seen.add(low)
        out.append(cand)
    return out


def heuristic_parse(raw: str, has_images: bool = False) -> dict:
    s = (raw or "").strip()
    if not s:
        return {"subject": "unknown subject (image)" if has_images else "",
                "subject_type": "person" if has_images else "name",
                "depth": "normal", "is_question": False, "raw": raw,
                "context": "", "aliases": [], "mode": "heuristic"}

    low = s.lower()
    depth = "deep" if any(k in low for k in _DEEP_HINTS) else "normal"
    is_question = (low.split()[:1] == ["who"]
                   or low.startswith(("what is this", "whose", "identify")))

    subject = None
    # An explicitly quoted segment is the subject; everything after it is
    # qualifying context ('"Alex Marsh" who is from AI Security Industry').
    qm = _QUOTED.search(s)
    if qm:
        subject = qm.group(1).strip()
    if not subject:
        m = re.search(r"\bthis is\s+(.+)", s, re.I)      # "this is X, ..."
        if m:
            cand = re.split(r"[,.;]| and | search| find| look| investigate| tell|"
                            r" please| research| dig", m.group(1),
                            maxsplit=1, flags=re.I)[0]
            subject = cand.strip()
    if not subject:                                       # strip command words
        cand = s
        for p in _STRIP:
            cand = re.sub(re.escape(p), " ", cand, flags=re.I)
        # cut a trailing qualifier clause off the subject before de-fillering,
        # so "Alex Marsh from AI Security Industry" -> subject "Alex Marsh".
        # Requires a plausible full name before the connective so that an
        # entity whose own name contains one ("University of California",
        # "Bank of America") is not truncated.
        lead = _CONTEXT_LEAD.search(cand)
        if lead and lead.start() > 0:
            prefix = cand[:lead.start()].strip()
            if (len(prefix.split()) >= _MIN_SUBJECT_WORDS_BEFORE_LEAD
                    and not _looks_like_org(prefix)):
                cand = prefix
        cand = _FILLER.sub(" ", cand)
        cand = _FILLER_PERSONWORDS.sub(" ", cand)
        cand = re.sub(r"\s+", " ", cand).strip(" ,.:;-\"'")
        subject = cand

    # trim dangling conjunctions left by command-word stripping
    subject = re.sub(r"^(?:and|or|of|for|the)\b\s*", "", subject, flags=re.I)
    subject = re.sub(r"\s*\b(?:and|or|of|for)\b$", "", subject, flags=re.I).strip()

    if not subject or len(subject) < 2:
        subject = "unknown subject (image)" if has_images else s

    if subject.startswith("unknown subject"):
        stype = "person" if has_images else "name"
    else:
        stype = classify_target(subject)
        # tidy an all-lowercase personal name
        if stype in ("name", "person") and subject == subject.lower():
            subject = subject.title()

    return {"subject": subject, "subject_type": stype, "depth": depth,
            "is_question": is_question, "raw": raw,
            "context": extract_context(raw, subject),
            "aliases": extract_aliases(raw, subject), "mode": "heuristic"}
