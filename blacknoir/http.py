"""The only place Black Noir touches the network.

Every request goes through `Fetcher`, which consults `Guardrails` first. If the
`requests` library is unavailable, or the target is refused, the fetcher fails
soft (returns None) so the agent degrades to plan-only mode instead of crashing.

TRANSPORT IDENTITY (BLACKNOIR_IMPERSONATE)
------------------------------------------
By default Black Noir identifies itself honestly: a `BlackNoir-OSINT/1.0` User-
Agent over Python's ordinary TLS stack. That is a deliberate posture, not an
oversight — it is the same commitment as the no-evasion rule in guardrails.py,
and it is *why* some engines refuse us.

`curl_cffi` (optional) can instead present a real browser's TLS/JA3 fingerprint.
Setting BLACKNOIR_IMPERSONATE=chrome (or firefox/safari/chrome131/…) turns that
on. It is OFF by default and must be chosen explicitly, because it changes how
the tool represents itself to every host it touches — that is the operator's
call to make knowingly, not a default to inherit.

Two things worth knowing before enabling it:
  * It is all-or-nothing. Impersonating a browser's TLS while sending a
    "BlackNoir-OSINT" User-Agent is a MORE anomalous fingerprint than either
    alone, so when impersonation is on the honest UA is dropped and curl_cffi's
    matching browser headers are used instead. You cannot be half-honest here.
  * It does not open login walls. Instagram/Facebook/LinkedIn want a session,
    not a friendlier handshake. This helps only with engines that fingerprint
    anonymous clients — and Serper already covers what those would return.
Nothing else changes: no onion fetch, no download, no link-following, and a
served challenge page is still reported as `blocked` rather than worked around.
"""

from __future__ import annotations

import os
import threading
from typing import Optional

from .config import HTTP_TIMEOUT, USER_AGENT
from .guardrails import Guardrails

try:  # optional dependency
    import requests  # type: ignore
    _HAS_REQUESTS = True
except Exception:  # pragma: no cover
    requests = None  # type: ignore
    _HAS_REQUESTS = False

try:  # optional: browser-grade TLS fingerprint
    from curl_cffi import requests as curl_requests  # type: ignore
    _HAS_CURL_CFFI = True
except Exception:  # pragma: no cover
    curl_requests = None  # type: ignore
    _HAS_CURL_CFFI = False


def _valid_impersonation_targets() -> set:
    """Every target curl_cffi actually accepts.

    Two namespaces, and both are needed: `REAL_TARGET_MAP` holds the aliases
    ("chrome", "firefox", "safari", "tor"), while the `BrowserType` enum holds
    the pinned versions ("chrome131", "safari18_0"). Neither contains the other.

    Validating up front matters because curl_cffi resolves `impersonate` LAZILY
    — constructing a Session with a typo succeeds and then raises
    ImpersonateError on every single request, which would surface as "every
    source is blocked" instead of "you misspelled a setting".
    """
    if not _HAS_CURL_CFFI:
        return set()
    try:
        from curl_cffi.requests.impersonate import (  # type: ignore
            REAL_TARGET_MAP, BrowserType)
        return {str(k).lower() for k in REAL_TARGET_MAP} | {
            str(b.value).lower() for b in BrowserType}
    except Exception:  # pragma: no cover - unknown curl_cffi layout
        return {"chrome", "firefox", "safari", "edge"}


def impersonation_target() -> str:
    """The configured browser to impersonate, or "" when honest (the default)."""
    val = os.environ.get("BLACKNOIR_IMPERSONATE", "").strip().lower()
    if val in ("", "off", "0", "false", "no", "none"):
        return ""
    return "chrome" if val in ("on", "1", "true", "yes") else val


def transport_status() -> str:
    """One line describing how this process presents itself on the wire."""
    target = impersonation_target()
    if not target:
        return "honest transport (BlackNoir UA, Python TLS)"
    if not _HAS_CURL_CFFI:
        return (f"BLACKNOIR_IMPERSONATE={target} requested but curl_cffi is not "
                f"installed — falling back to honest transport")
    if target not in _valid_impersonation_targets():
        return (f"BLACKNOIR_IMPERSONATE={target!r} is not a target curl_cffi "
                f"supports — falling back to honest transport. Try 'chrome', "
                f"'firefox', 'safari' or 'edge'.")
    return f"impersonating {target} (browser TLS + matching headers)"


class Fetcher:
    def __init__(self, guard: Guardrails, live: bool = False) -> None:
        self.guard = guard
        self.live = live
        # Either transport can carry a request, so either one makes us live-capable.
        self.available = _HAS_REQUESTS or _HAS_CURL_CFFI
        # Last transport failure as (status_code, body_snippet). Connectors read
        # this to report *why* a source failed instead of guessing — a 400
        # "query pattern not allowed" is a fixable bug, not a rate limit.
        self.last_error: Optional[tuple] = None
        self.last_status: Optional[int] = None
        # requests.Session isn't thread-safe, so each thread gets its own.
        # Parallel probes (the username sweep) therefore never share a pool.
        self._local = threading.local()

    @property
    def _session(self):
        """Lazily create one session per thread (curl_cffi or requests)."""
        if not (self.available and self.live):
            return None
        sess = getattr(self._local, "session", None)
        if sess is not None:
            return sess

        target = impersonation_target()
        if target and _HAS_CURL_CFFI and target in _valid_impersonation_targets():
            try:
                # curl_cffi sets a coherent browser header set to match the TLS
                # fingerprint, so we deliberately do NOT overwrite User-Agent
                # here — a browser handshake carrying a scraper UA is a louder
                # signal than either half on its own.
                sess = curl_requests.Session(impersonate=target)
                self._local.session = sess
                return sess
            except Exception:
                # Unknown/unsupported target: fall through to honest transport
                # rather than failing the run. Reported by transport_status().
                pass

        if not _HAS_REQUESTS:
            return None
        sess = requests.Session()
        sess.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })
        self._local.session = sess
        return sess

    def get(self, url: str) -> Optional[str]:
        """GET a clearnet search page. Returns body text or None."""
        allowed, reason = self.guard.can_fetch(url)
        if not allowed:
            # Keep the refusal reason: our own allow-list rejecting a source is
            # a configuration bug, and it must not be reported to the operator
            # as an indistinguishable "no response (blocked/timeout)".
            self.last_status = None
            self.last_error = (None, f"guardrail:{reason}")
            return None
        if not self.live:
            self.guard.note("plan", url, "plan-mode:no-network")
            return None
        if not self.available:
            self.guard.note("skip", url, "no-http-transport-installed")
            return None
        try:
            resp = self._session.get(url, timeout=HTTP_TIMEOUT)  # type: ignore
            self.last_status = resp.status_code
            if resp.status_code >= 400:
                self.last_error = (resp.status_code, (resp.text or "")[:300])
                self.guard.note("error", url, f"http-{resp.status_code}")
                return None
            self.last_error = None
            return resp.text
        except Exception as exc:  # network errors are non-fatal
            self.last_status = None
            self.last_error = (None, f"{type(exc).__name__}: {exc}"[:300])
            self.guard.note("error", url, f"exc:{type(exc).__name__}")
            return None

    def probe(self, url: str, headers: Optional[dict] = None,
              timeout: Optional[float] = None):
        """GET returning (status_code, text) for presence checks (username sweep).

        Guarded + live-only + no-download like every other call. Returns
        (None, None) when refused, offline, or errored. Unlike get(), it does
        NOT treat a 404 as failure — the caller needs the code to tell
        'account missing' (404) from 'account exists' (200 + marker string).
        """
        allowed, _ = self.guard.can_fetch(url)
        if not allowed or not self.live or not self.available:
            if not self.live:
                self.guard.note("plan", url, "plan-mode:no-network")
            return None, None
        try:
            resp = self._session.get(  # type: ignore
                url, timeout=timeout or HTTP_TIMEOUT, headers=headers or {},
                allow_redirects=True)
            return resp.status_code, resp.text
        except Exception as exc:
            self.guard.note("error", url, f"exc:{type(exc).__name__}")
            return None, None

    def post(self, url: str, files: Optional[dict] = None,
             data: Optional[dict] = None, json_body: Optional[dict] = None,
             headers: Optional[dict] = None, as_json: bool = False):
        """POST to a clearnet endpoint (reverse-image upload or SERP API). Guarded.

        An outbound POST (uploading a local image, or querying a search API)
        passes the same allow-list as GET and only happens in --live mode.
        Returns text/json body or None.
        """
        allowed, reason = self.guard.can_fetch(url)
        if not allowed:
            return None
        if not self.live:
            self.guard.note("plan", url, "plan-mode:no-post")
            return None
        if not self.available:
            self.guard.note("skip", url, "no-http-transport-installed")
            return None
        self.guard.note("upload" if files else "post", url,
                        "reverse-image upload" if files else "api-post")
        try:
            resp = self._session.post(  # type: ignore
                url, files=files, data=data, json=json_body,
                headers=headers or {}, timeout=HTTP_TIMEOUT)
            if resp.status_code >= 400:
                self.last_error = (resp.status_code, (resp.text or "")[:300])
                self.guard.note("error", url, f"http-{resp.status_code}")
                return None
            self.last_error = None
            return resp.json() if as_json else resp.text
        except Exception as exc:
            self.last_error = (None, f"{type(exc).__name__}: {exc}"[:300])
            self.guard.note("error", url, f"exc:{type(exc).__name__}")
            return None

    def get_json(self, url: str, headers: Optional[dict] = None,
                 timeout: Optional[float] = None) -> Optional[dict]:
        allowed, reason = self.guard.can_fetch(url)
        if not allowed or not self.live or not self.available:
            if not self.live:
                self.guard.note("plan", url, "plan-mode:no-network")
            return None
        try:
            resp = self._session.get(  # type: ignore
                url, timeout=timeout or HTTP_TIMEOUT, headers=headers or {}
            )
            if resp.status_code == 404:
                return {"__status__": 404}
            if resp.status_code >= 400:
                self.guard.note("error", url, f"http-{resp.status_code}")
                return None
            return resp.json()
        except Exception as exc:
            self.guard.note("error", url, f"exc:{type(exc).__name__}")
            return None
