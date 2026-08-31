"""Multi-provider LLM abstraction.

One uniform interface over several OpenAI-compatible backends:

  * google      -> Google AI Studio, via its OpenAI-compatible /v1beta/openai
  * nvidia      -> NVIDIA NIM, via its OpenAI-compatible /v1
  * groq        -> Groq, via its OpenAI-compatible /openai/v1
  * cloudflare  -> Cloudflare Workers AI, via its account /ai/v1
  * siliconflow -> SiliconFlow, via its OpenAI-compatible /v1
  * openrouter  -> OpenRouter aggregator, via /api/v1
  * ollama      -> local Ollama, via its OpenAI-compatible /v1 (auto-started)

Every provider speaks the OpenAI wire format, so a single `_OpenAICompat`
backend serves all of them just by swapping base_url + key.

The class degrades gracefully: if the SDK or credentials are missing, or a call
fails, methods return None and the Agent falls back to deterministic heuristics.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import urlparse


@dataclass
class ProviderSpec:
    name: str
    kind: str            # "openai" (all providers use the OpenAI wire format)
    key_env: Optional[str]
    model_env: str
    default_model: str
    base_env: Optional[str]
    default_base: Optional[str] = None


SPECS: dict[str, ProviderSpec] = {
    # HKGAI (hkchat.app MaaS) — a Hong Kong provider, so it is NOT geo-blocked
    # the way Google's Gemini API is in HK. Three slots so the multi-agent panel
    # can fan out across three models on three keys. OpenAI-compatible endpoint.
    # Placed first in AUTO_ORDER so it is the primary + fills the panel before
    # the flaky/blocked providers below. Config lives in .env (HKGAI_* vars).
    "hkgai": ProviderSpec("hkgai", "openai", "HKGAI_API_KEY",
                          "HKGAI_MODEL", "t2_deepseek-v4-flash-0731_fp8_1m",
                          "HKGAI_BASE_URL",
                          "https://test-new-api.hkchat.app/v1"),
    "hkgai2": ProviderSpec("hkgai2", "openai", "HKGAI_API_KEY2",
                           "HKGAI_MODEL2", "t2_qwen3-8-27b_fp8_262k",
                           "HKGAI_BASE_URL",
                           "https://test-new-api.hkchat.app/v1"),
    "hkgai3": ProviderSpec("hkgai3", "openai", "HKGAI_API_KEY3",
                           "HKGAI_MODEL3", "t2_gpt-oss-120b_mxfp4_128k",
                           "HKGAI_BASE_URL",
                           "https://test-new-api.hkchat.app/v1"),
    "google": ProviderSpec("google", "openai", "GOOGLE_API_KEY",
                           "GOOGLE_MODEL", "gemini-flash-lite-latest",
                           "GOOGLE_BASE_URL",
                           "https://generativelanguage.googleapis.com/v1beta/openai"),
    # NOTE: meta/llama-3.1-70b-instruct was retired by NVIDIA (the endpoint
    # answers HTTP 410 Gone). It sat first in the failover chain, so every
    # fallback from Google landed on a permanently dead model and the whole
    # agent silently degraded to heuristics. Verified live 2026-08-27.
    "nvidia": ProviderSpec("nvidia", "openai", "NVIDIA_API_KEY",
                           "NVIDIA_MODEL", "nvidia/nemotron-3-super-120b-a12b",
                           "NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1"),
    "groq": ProviderSpec("groq", "openai", "GROQ_API_KEY",
                         "GROQ_MODEL", "qwen/qwen3.8-27b",
                         "GROQ_BASE_URL", "https://api.groq.com/openai/v1"),
    "openrouter": ProviderSpec("openrouter", "openai", "OPENROUTER_API_KEY",
                               "OPENROUTER_MODEL",
                               "nvidia/nemotron-3.5-lightning:free",
                               "OPENROUTER_BASE_URL",
                               "https://openrouter.ai/api/v1"),
    "siliconflow": ProviderSpec("siliconflow", "openai", "SILICONFLOW_API_KEY",
                                "SILICONFLOW_MODEL", "Qwen/Qwen2.5-7B-Instruct",
                                "SILICONFLOW_BASE_URL",
                                "https://api.siliconflow.com/v1"),
    # Cloudflare Workers AI: the account id is part of the base URL, so set
    # CLOUDFLARE_BASE_URL to .../accounts/<ACCOUNT_ID>/ai/v1 and the token in
    # CLOUDFLARE_API_TOKEN.
    "cloudflare": ProviderSpec("cloudflare", "openai", "CLOUDFLARE_API_TOKEN",
                               "CLOUDFLARE_MODEL",
                               "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
                               "CLOUDFLARE_BASE_URL", None),
    "ollama": ProviderSpec("ollama", "openai", None,
                           "OLLAMA_MODEL", "llama3.1", "OLLAMA_BASE_URL",
                           "http://localhost:11434"),
}

# Auto-detection / panel priority. Fast, direct-hosted providers first; the
# slower aggregator (OpenRouter free tier) comes after them so it only joins at
# a larger --panel-size; Ollama last as it is local.
AUTO_ORDER = ["hkgai", "hkgai2", "hkgai3", "google", "nvidia", "groq",
              "cloudflare", "siliconflow", "openrouter", "ollama"]

_VISION_HINTS = ("vision", "llava", "-vl", "gpt-4o", "gpt-4.1", "o4", "gemini",
                 "claude", "llama-3.2-vision", "pixtral")

# HTTP statuses that mean "this provider will never work with this config":
# a retired/unknown model (404/410), a bad or revoked key (401/403), or an
# exhausted prepaid balance (402). Retrying these wastes the run, and — worse —
# spending the failover budget on them is how a healthy provider further down
# the chain never gets reached.
_PERMANENT_STATUS = {401, 402, 403, 404, 410}


def _is_permanent(exc: Exception) -> bool:
    """True when retrying `exc` on this provider cannot possibly succeed."""
    code = getattr(exc, "status_code", None)
    if code is None:
        resp = getattr(exc, "response", None)
        code = getattr(resp, "status_code", None)
    msg = f"{exc}".lower()
    # A geo-block is permanent for the session even though it arrives as a 400
    # (normally a transient bad request): Google's free Gemini API answers
    # 400 FAILED_PRECONDITION "User location is not supported for the API use"
    # in unsupported regions (e.g. Hong Kong). Left un-retired, it burns two
    # failed attempts on EVERY LLM call for the whole run and starves the
    # working providers below it — which is how synthesis silently degrades.
    if ("user location is not supported" in msg
            or "location is not supported" in msg
            or "failed_precondition" in msg):
        return True
    if isinstance(code, int):
        return code in _PERMANENT_STATUS
    # Fall back to the class name for SDKs that don't expose a status.
    return type(exc).__name__ in (
        "NotFoundError", "AuthenticationError", "PermissionDeniedError")


def _log(cb: Optional[Callable[[str], None]], msg: str) -> None:
    if cb:
        cb(msg)


# --- model output parsing ---------------------------------------------------

def _balanced_objects(text: str):
    """Yield every balanced {...} span in `text`, outermost-first.

    Brace counting is string-aware, so a '}' inside a JSON string value does
    not close the object. A span that never balances (the model was cut off
    mid-object) is skipped rather than yielded half-formed.
    """
    depth = start = 0
    in_str = esc = False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth:
                depth -= 1
                if depth == 0:
                    yield text[start:i + 1]


def json_from_model(out: Optional[str]):
    """Extract the JSON object a model meant to return, or None.

    Reasoning models narrate before answering, and that narration contains
    braces, quoted schema fragments and worked examples. Slicing from the first
    '{' to the last '}' therefore captures prose and fails to parse — which the
    callers used to swallow, silently downgrading the whole run to heuristics.
    The LAST well-formed object wins: a model that echoes the schema and then
    answers puts its real answer last.
    """
    if not out:
        return None
    text = out.strip()
    import json as _json
    import re as _re

    def _load(seg: str):
        try:
            obj = _json.loads(seg)
        except Exception:
            return None
        return obj if isinstance(obj, dict) and obj else None

    # A fenced block is an explicit "this is the answer" marker; prefer it.
    for block in reversed(_re.findall(r"```(?:json)?\s*(.*?)```", text, _re.S)):
        for cand in reversed(list(_balanced_objects(block))):
            obj = _load(cand)
            if obj is not None:
                return obj
    for cand in reversed(list(_balanced_objects(text))):
        obj = _load(cand)
        if obj is not None:
            return obj
    return None


# --- Ollama lifecycle -------------------------------------------------------

def _http_ok(url: str, timeout: float = 2.0) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status < 500
    except Exception:
        return False


def _port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def ensure_ollama(base_url: str, model: str,
                  log: Optional[Callable[[str], None]] = None) -> bool:
    """Make sure a local Ollama server is listening at base_url.

    If it is not, spawn `ollama serve` bound to the requested host:port and wait
    for it to come up. Returns True when the server is reachable.
    """
    parsed = urlparse(base_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 11434
    root = f"http://{host}:{port}"

    if _port_open(host, port):
        _log(log, f"ollama already running at {root}")
        return True

    exe = shutil.which("ollama")
    if not exe:
        _log(log, "ollama not installed / not on PATH — cannot auto-start")
        return False

    env = dict(os.environ)
    env["OLLAMA_HOST"] = f"{host}:{port}"  # bind serve to the configured port
    _log(log, f"starting `ollama serve` on {host}:{port} …")
    try:
        creation = 0
        if sys.platform == "win32":
            creation = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        subprocess.Popen(
            [exe, "serve"], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=creation,
        )
    except Exception as exc:
        _log(log, f"failed to launch ollama serve: {exc}")
        return False

    for _ in range(30):  # wait up to ~15s for the daemon
        if _port_open(host, port):
            _log(log, "ollama server is up")
            _ensure_model(host, port, model, log)
            return True
        time.sleep(0.5)
    _log(log, "ollama did not become ready in time")
    return False


def _ensure_model(host: str, port: int, model: str,
                  log: Optional[Callable[[str], None]]) -> None:
    """Warn (do not block) if the requested model is not pulled yet."""
    try:
        with urllib.request.urlopen(
                f"http://{host}:{port}/api/tags", timeout=3) as r:
            import json
            tags = json.loads(r.read().decode("utf-8"))
        have = {m.get("name", "") for m in tags.get("models", [])}
        if model not in have and not any(t.startswith(model.split(":")[0])
                                         for t in have):
            _log(log, f"model '{model}' not pulled — run: ollama pull {model}")
    except Exception:
        pass


# --- backends ---------------------------------------------------------------

class _OpenAICompat:
    def __init__(self, model: str, key: str, base_url: str) -> None:
        from openai import OpenAI  # raises if missing
        self.model = model
        self._c = OpenAI(api_key=key or "not-needed", base_url=base_url)

    def text(self, system: str, prompt: str, max_tokens: int) -> Optional[str]:
        r = self._c.chat.completions.create(
            model=self.model, max_tokens=max_tokens,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": prompt}])
        return r.choices[0].message.content

    def vision(self, system: str, prompt: str, b64: str, media: str,
               max_tokens: int) -> Optional[str]:
        data_uri = f"data:{media};base64,{b64}"
        r = self._c.chat.completions.create(
            model=self.model, max_tokens=max_tokens,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": [
                          {"type": "text", "text": prompt},
                          {"type": "image_url",
                           "image_url": {"url": data_uri}}]}])
        return r.choices[0].message.content


# --- public LLM facade ------------------------------------------------------

class LLM:
    # Class-level defaults so an instance built with __new__ (the vision and
    # failover unit tests, and any future partial construction) still has sane
    # failover state instead of raising AttributeError inside the error path.
    _ok_calls = 0
    provider: Optional[str] = None
    model: Optional[str] = None

    def __init__(self, provider: Optional[str] = None,
                 model: Optional[str] = None, use_llm: bool = True,
                 log: Optional[Callable[[str], None]] = None) -> None:
        self.provider = None
        self.model = None
        self.backend = None
        self.vision_ok = False
        self.status = "heuristic"
        self._log = log
        self._model_override = model
        self._errors = 0
        self.last_error: Optional[str] = None   # real cause of the last failure
        self._idx = 0
        self._chain: list[str] = []
        # Providers proven unusable this session (retired model, bad key, no
        # balance) — never routed to again.
        self._dead: set[str] = set()
        # Successful calls on the CURRENT provider. Zero means unproven, and an
        # unproven provider is not worth spending a real call to re-test.
        self._ok_calls = 0
        self.error_threshold = int(os.environ.get("BLACKNOIR_ERROR_THRESHOLD", "2"))

        if not use_llm:
            self.status = "heuristic (disabled)"
            return

        primary = self._resolve(provider)
        if not primary:
            self.status = "heuristic (no provider configured)"
            return

        # Failover chain: the resolved provider first, then every other
        # available provider (in preference order) to jump to on repeated errors.
        others = [p for p in AUTO_ORDER
                  if p != primary and self._available(p)]
        self._chain = [primary] + others

        if self._activate_from(0):
            self.status = "llm"
        else:
            self.status = "heuristic (no provider could start)"

    # -- provider construction / failover ------------------------------------

    def _build_backend(self, name: str, use_override: bool):
        spec = SPECS[name]
        model = ((self._model_override if use_override and self._model_override
                  else None) or os.environ.get(spec.model_env)
                 or spec.default_model)
        base = (os.environ.get(spec.base_env) if spec.base_env else None) \
            or spec.default_base
        key = os.environ.get(spec.key_env, "") if spec.key_env else ""
        if name == "ollama":
            if not ensure_ollama(base, model, self._log):
                raise RuntimeError("ollama unavailable")
            return _OpenAICompat(model, "ollama", base.rstrip("/") + "/v1"), model
        return _OpenAICompat(model, key, base), model

    def _activate_from(self, start: int) -> bool:
        for i in range(start, len(self._chain)):
            name = self._chain[i]
            if name in getattr(self, "_dead", ()):   # proven unusable already
                continue
            try:
                backend, model = self._build_backend(name, use_override=(i == 0))
            except Exception as exc:
                if self._log:
                    self._log(f"provider '{name}' unavailable "
                              f"({type(exc).__name__}); trying next")
                continue
            self._idx, self.provider, self.model = i, name, model
            self.backend, self.vision_ok = backend, _vision_capable(model)
            self._errors = 0
            self._ok_calls = 0        # the new provider is unproven until it answers
            return True
        self.backend = self.provider = None
        return False

    def _advance(self) -> bool:
        prev = self.provider
        if self._activate_from(self._idx + 1):
            if self._log:
                self._log(f"failover: '{prev}' -> '{self.provider}:{self.model}' "
                          "after repeated errors")
            return True
        return False

    def _invoke(self, method: str, *args):
        if not self.enabled:
            self.last_error = "no LLM provider enabled"
            return None
        hops = 0
        while True:
            try:
                out = getattr(self.backend, method)(*args)
                self._errors = 0
                self._ok_calls += 1
                self.last_error = None
                return out
            except Exception as exc:
                # Keep the real cause. Swallowing it turns an expired key or a
                # size limit into an unexplained "call failed", which reads as
                # "there was nothing to find".
                self.last_error = f"{type(exc).__name__}: {exc}"[:300]
                self._errors += 1
                if _is_permanent(exc):
                    # Dead for the whole session: a retired model or a rejected
                    # key will answer identically every time. Retire it so the
                    # rest of the run stops routing through it.
                    dead = getattr(self, "_dead", None)
                    if dead is None:
                        dead = self._dead = set()
                    dead.add(self.provider)
                    if self._log:
                        self._log(f"provider '{self.provider}:{self.model}' is "
                                  f"permanently unusable ({self.last_error[:70]})"
                                  " — retiring it for this session")
                    give_up = False
                elif self._ok_calls == 0:
                    # An unproven provider gets no tolerance. Spending the very
                    # first call of a run discovering that the primary is out of
                    # quota is exactly how a whole investigation silently drops
                    # to heuristics while a healthy provider sits unused.
                    give_up = False
                else:
                    # A provider that has actually worked earns some patience:
                    # one blip should not cost us a model we know is good.
                    give_up = self._errors < self.error_threshold
                if not give_up and hops < len(self._chain) and self._advance():
                    hops += 1
                    continue
                return None

    # -- resolution ----------------------------------------------------------

    @staticmethod
    def _available(name: str) -> bool:
        spec = SPECS[name]
        if name == "ollama":
            base = os.environ.get(spec.base_env or "", "") or spec.default_base
            p = urlparse(base)
            return _port_open(p.hostname or "localhost", p.port or 11434) \
                or bool(shutil.which("ollama"))
        return bool(os.environ.get(spec.key_env or ""))

    def _resolve(self, explicit: Optional[str]) -> Optional[str]:
        # Precedence: explicit specific provider > BLACKNOIR_PROVIDER > auto.
        # "auto" (or unset) at any level defers to the next level, then to
        # auto-detection — so 'auto' is a safe default.
        cand = (explicit or "").strip().lower()
        if not cand or cand == "auto":
            cand = (os.environ.get("BLACKNOIR_PROVIDER") or "").strip().lower()
        if cand and cand != "auto":
            return cand if cand in SPECS else None
        for name in AUTO_ORDER:            # auto-detect first available
            if self._available(name):
                return name
        return None

    # -- API -----------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        return self.backend is not None

    @property
    def label(self) -> str:
        if not self.enabled:
            return self.status
        extra = " (+failover)" if len(self._chain) > 1 else ""
        return f"{self.provider}:{self.model}{extra}"

    def complete_text(self, system: str, prompt: str,
                      max_tokens: int = 1200) -> Optional[str]:
        return self._invoke("text", system, prompt, max_tokens)

    def complete_vision(self, system: str, prompt: str, b64: str, media: str,
                        max_tokens: int = 700) -> Optional[str]:
        if not self.enabled:
            return None
        if not self.vision_ok:
            return f"(vision unsupported by {self.provider}:{self.model})"
        out = self._invoke("vision", system, prompt, b64, media, max_tokens)
        if out is not None:
            return out
        why = getattr(self, "last_error", None) or "no response"
        return f"(vision call failed: {why})"


def _vision_capable(model: str) -> bool:
    m = (model or "").lower()
    return any(h in m for h in _VISION_HINTS)


# --- multi-agent panel helpers ----------------------------------------------

def _panel_ollama_optin() -> bool:
    """Ollama joins the multi-agent panel only when explicitly opted in — it is
    local and slow, so it is not worth blocking a fan-out on by default."""
    return os.environ.get("BLACKNOIR_PANEL_OLLAMA", "").strip().lower() in (
        "1", "true", "yes", "on")


def multi_agent_enabled() -> bool:
    """Multi-agent planning is on by default; disable with BLACKNOIR_MULTI_AGENT=0."""
    return os.environ.get("BLACKNOIR_MULTI_AGENT", "1").strip().lower() not in (
        "0", "false", "no", "off")


# How many models the panel uses (INCLUDING the primary). More models = more
# query diversity but more latency + rate-limit pressure; past ~3 the query
# sets overlap heavily. Default 3 keeps the panel to the fast, reliable cloud
# providers (the slower aggregators sit later in AUTO_ORDER, so they only join
# at a larger --panel-size or 'all'). "all" uses every available provider.
DEFAULT_PANEL_SIZE = 3


def panel_size(override: Optional[str] = None) -> int:
    """Total models to plan with (primary + panel). 'all'/0/negative => no cap."""
    raw = (override if override is not None
           else os.environ.get("BLACKNOIR_PANEL_SIZE", "")).strip().lower()
    if raw in ("all", "max", "-1", "0"):
        return 10_000
    if raw.isdigit():
        return max(1, int(raw))
    return DEFAULT_PANEL_SIZE


def available_providers(include_ollama: bool = False) -> list[str]:
    """Providers ready to use right now (key present, or Ollama reachable), in
    AUTO_ORDER preference. Ollama is excluded unless include_ollama is set or
    BLACKNOIR_PANEL_OLLAMA is truthy — it is too slow to fan out on by default."""
    inc = include_ollama or _panel_ollama_optin()
    names = []
    for name in AUTO_ORDER:
        if name == "ollama" and not inc:
            continue
        if LLM._available(name):
            names.append(name)
    return names
