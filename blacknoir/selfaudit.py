"""Self-audit checks — exposure questions you ask about your OWN identifiers.

Self-audit is a fundamentally easier problem than investigating a stranger: the
identity is already known, so none of the candidate-resolution machinery is
needed. What matters instead is breadth and recall — checking the things you
would not think to check, and the accounts you have forgotten you made.

Currently:
  * `check_password_pwned` — Have I Been Pwned's keyless Pwned Passwords range
    API, using k-anonymity so the password never leaves this machine.
"""

from __future__ import annotations

import hashlib

from .config import USER_AGENT

_PP_RANGE = "https://api.pwnedpasswords.com/range/"


def check_password_pwned(password: str, fetcher) -> dict:
    """Return {'status', 'count', 'detail'} for one password.

    Uses the k-anonymity range API: we send the FIRST FIVE characters of the
    SHA-1 hash and nothing else. The service replies with every hash suffix it
    holds under that prefix (typically ~800 of them) and the match is done here,
    locally. The password, its full hash, and even which of the returned hashes
    was ours never leave this machine — so this is safe to run on a password you
    are actually using, which is the only way the check is worth anything.

    This is the one breach signal that is completely free and keyless: HIBP
    gates per-ACCOUNT lookup behind a paid key, but per-PASSWORD lookup is open.
    """
    if not password:
        return {"status": "skipped", "count": 0,
                "detail": "no password supplied"}
    if not getattr(fetcher, "live", False):
        return {"status": "planned", "count": 0,
                "detail": "plan-only; would query the Pwned Passwords range API "
                          "(k-anonymity, password never transmitted)."}

    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]

    # `probe`, not `get`: get() takes no headers, and we need "Add-Padding" so
    # the response size cannot leak how many hashes share our prefix.
    status, body = fetcher.probe(_PP_RANGE + prefix,
                                 headers={"User-Agent": USER_AGENT,
                                          "Add-Padding": "true"})
    if status != 200 or not body:
        return {"status": "blocked", "count": 0,
                "detail": (f"no usable response from the Pwned Passwords API "
                           f"(HTTP {status})." if status else
                           "no response from the Pwned Passwords API.")}

    for line in body.splitlines():
        part, _, count = line.strip().partition(":")
        if part.upper() != suffix:
            continue
        try:
            n = int(count.replace(",", "").strip())
        except ValueError:
            n = 0
        # Padding rows are returned with a count of 0 to disguise the real
        # response size; a 0 here means "not actually present".
        if n <= 0:
            break
        return {
            "status": "pwned", "count": n,
            "detail": (f"This password appears {n:,} time(s) in known breach "
                       f"corpora. It is in the wordlists attackers try first — "
                       f"change it anywhere it is used, and do not reuse it."),
        }

    return {"status": "clean", "count": 0,
            "detail": ("Not found in the Pwned Passwords corpus. That means it "
                       "has not appeared in a breach HIBP has indexed — it does "
                       "not mean the password is strong, or that an account "
                       "using it was never breached.")}


def summarize(result: dict) -> str:
    """One-line human summary for the CLI."""
    st = result.get("status")
    if st == "pwned":
        return f"COMPROMISED — seen {result.get('count', 0):,} time(s) in breaches"
    if st == "clean":
        return "not found in any indexed breach corpus"
    return f"{st}: {result.get('detail', '')}"
