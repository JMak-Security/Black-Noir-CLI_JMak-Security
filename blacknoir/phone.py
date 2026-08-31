"""Keyless structural analysis of a phone number.

A phone number carries real, checkable information in its own digits — country,
line type, whether the carrier is even knowable — and none of it needs an API
key, a network call, or a data broker. Black Noir previously had nothing here:
a phone target produced web queries and, without NUMVERIFY_API_KEY, no
enrichment at all, so a run could return "nothing found" while never stating
the things the number itself says out loud.

What this deliberately does NOT do: name the subscriber. No public mobile
subscriber directory exists in Hong Kong (or most places), and the only sources
that claim otherwise are data brokers whose records are stale and frequently
wrong. Reporting a broker guess as an identity is how an OSINT tool libels
someone. So the honest output is structure plus an explicit statement of what
cannot be determined.
"""

from __future__ import annotations

import re

from .models import SearchResult, SourceRun

# Country calling codes worth naming. Not exhaustive — an unknown code is
# reported as unknown rather than guessed.
_CC = {
    "852": "Hong Kong", "853": "Macau", "886": "Taiwan", "86": "China",
    "65": "Singapore", "60": "Malaysia", "81": "Japan", "82": "South Korea",
    "63": "Philippines", "66": "Thailand", "84": "Vietnam", "62": "Indonesia",
    "91": "India", "44": "United Kingdom", "1": "US/Canada (NANP)",
    "61": "Australia", "64": "New Zealand", "49": "Germany", "33": "France",
    "34": "Spain", "39": "Italy", "31": "Netherlands", "7": "Russia/Kazakhstan",
    "971": "United Arab Emirates", "966": "Saudi Arabia", "27": "South Africa",
    "55": "Brazil", "52": "Mexico",
}

# Line-type rules are per-country and only encoded where they are firm.
# Hong Kong (OFCA numbering plan): 8 digits, no area codes.
_HK_PREFIX = {
    "2": "fixed line", "3": "fixed line",
    "4": "mobile (later allocation)",
    "5": "mobile", "6": "mobile", "9": "mobile",
    "7": "pager (legacy allocation)",
    "8": "special / personal number service",
}


# Fixed national-number lengths, used only to disambiguate a missing "+".
# Deliberately limited to plans with ONE national length — a country with
# variable-length numbers cannot be identified this way without guessing.
_NATIONAL_LENGTH = {"852": 8, "853": 8, "65": 8, "886": 9}


def normalise(raw: str) -> tuple[str, str]:
    """Return (country_code, national_digits) — both '' when unparseable."""
    digits = re.sub(r"[^\d+]", "", raw or "")
    if digits.startswith("00"):
        digits = "+" + digits[2:]
    if not digits.startswith("+"):
        bare = re.sub(r"\D", "", digits)
        # People write "5550-0100" as often as "+852 5550 0100". Accept a
        # leading country code without the plus ONLY when the remaining length
        # matches that country's plan exactly — otherwise "8526280..." is
        # genuinely ambiguous and guessing would mislabel the region.
        for code, national_len in _NATIONAL_LENGTH.items():
            if bare.startswith(code) and len(bare) == len(code) + national_len:
                return code, bare[len(code):]
        return "", bare
    body = digits[1:]
    for length in (3, 2, 1):            # longest code first
        if body[:length] in _CC:
            return body[:length], body[length:]
    return "", body


def analyse(raw: str) -> dict:
    """Everything derivable from the digits alone. No network, no key."""
    cc, national = normalise(raw)
    out = {
        "input": raw, "country_code": cc, "national": national,
        "country": _CC.get(cc, ""), "line_type": "", "carrier": "",
        "notes": [],
    }
    if not cc:
        out["notes"].append(
            "No country code supplied, so region and line type cannot be "
            "determined. Provide the number in +<country><number> form.")
        return out

    if not out["country"]:
        out["notes"].append(f"Country code +{cc} is not in this table.")

    if cc == "852":
        if len(national) != 8:
            out["notes"].append(
                f"Hong Kong numbers are 8 digits; got {len(national)}. "
                f"This may be mistyped or include an extension.")
        lead = national[:1]
        out["line_type"] = _HK_PREFIX.get(lead, "unallocated/unknown block")
        out["notes"].append(
            "Hong Kong has no area codes — the leading digit indicates the "
            "service block, not a location, so the number reveals nothing "
            "about where the holder lives.")
        # The single most useful fact, and the one people most often get wrong.
        out["carrier"] = "not determinable"
        out["notes"].append(
            "Carrier CANNOT be inferred from the prefix: Hong Kong has had "
            "full mobile number portability since 1999, so the original "
            "allocation block says nothing about the current operator.")
        if "mobile" in out["line_type"]:
            out["notes"].append(
                "Mobile line: there is no public subscriber directory for Hong "
                "Kong mobiles, so no legitimate source names the holder. Any "
                "site claiming to is a data broker guessing.")
    else:
        out["notes"].append(
            "Line-type rules are encoded for Hong Kong only; for other "
            "countries this reports region but not line type.")
    return out


def exposure_advice(info: dict) -> list[str]:
    """What a phone number actually leaks — the self-audit answer.

    A number's real exposure is almost never a directory listing. It is the
    messaging apps that show a profile name and photo to anyone who saves the
    number as a contact, which is checkable by the number's owner in seconds
    and invisible to any search engine.
    """
    tips = [
        "Save the number as a contact and open WhatsApp, Signal and Telegram: "
        "each may show a display name and profile photo to anyone holding the "
        "number. That is the largest real exposure a phone number carries, and "
        "it is self-published — tighten it in each app's privacy settings.",
        "Check whether the number is used as a recovery/2FA contact anywhere; "
        "a leaked number plus an account name is the usual takeover path.",
    ]
    if info.get("country_code") == "852":
        tips.append(
            "Hong Kong: check the number against Scameter "
            "(cyberdefender.hk/en-us/scameter/) and, if it called you, the "
            "Anti-Deception Coordination Centre helpline 18222.")
    return tips


def run_phone(raw: str) -> SourceRun:
    """SourceRun so the existing report renders this like any other finding."""
    info = analyse(raw)
    results: list[SearchResult] = []
    headline = " · ".join(x for x in (
        info.get("country"), info.get("line_type"),
        (f"carrier {info['carrier']}" if info.get("carrier") else "")) if x)
    if headline:
        results.append(SearchResult(
            "phone_structure", "public",
            title=f"{raw} — {headline}"[:200],
            snippet="derived from the numbering plan; no lookup performed",
            meta={k: info[k] for k in ("country_code", "country", "line_type",
                                       "carrier")}))
    for note in info["notes"]:
        results.append(SearchResult("phone_structure", "public",
                                    title=note[:200], snippet=""))
    return SourceRun(
        "phone_structure", "Phone number structure (keyless)", "public",
        "ok" if results else "empty",
        detail=("offline analysis of the numbering plan — no API, no network, "
                "no data broker. Does not and cannot name the subscriber."),
        results=results)
