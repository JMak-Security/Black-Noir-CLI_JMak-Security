"""Investigation memory — remember resolved identities between runs.

Re-running a search on the same person normally starts from zero: the same
recon sweep, the same namesakes, the same rounds spent re-learning that this
"Alex Marsh" is the one at a given employer. This module keeps what a previous
run *confirmed* so the next one starts warm — extra opening queries built from
the known employer/handles, and a clustering step told which identity was
previously established.

PRIVACY
-------
This file holds personal data about people who were searched: names, employers,
locations, profile URLs. It is therefore:

  * local only — a JSON file beside your reports; nothing is ever transmitted
  * inspectable — `--list-memory` prints everything held, in full
  * erasable    — `--forget "<target>"` or `--forget-all`, no soft-delete
  * optional    — `--memory off`, or BLACKNOIR_MEMORY=off, records nothing

Deletion is real: the entry is removed from the file on write, not tombstoned.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from typing import Optional

MEMORY_VERSION = 1
DEFAULT_DIR = os.environ.get("BLACKNOIR_MEMORY_DIR", "memory")
FILENAME = "investigations.json"
# Cap so the store cannot grow without bound; oldest-touched entries drop first.
MAX_ENTRIES = int(os.environ.get("BLACKNOIR_MEMORY_MAX", "200"))


def enabled(flag: str = "auto") -> bool:
    """Memory is on unless explicitly disabled by flag or environment."""
    if flag == "off":
        return False
    return os.environ.get("BLACKNOIR_MEMORY", "auto").strip().lower() != "off"


def _path(memory_dir: str = DEFAULT_DIR) -> str:
    return os.path.join(memory_dir, FILENAME)


def key_for(target: str, context: str = "") -> str:
    """Stable identity key. Context is part of it: the same name with a
    different qualifier is a different investigation, not an update."""
    t = re.sub(r"\s+", " ", (target or "").strip().lower())
    c = re.sub(r"\s+", " ", (context or "").strip().lower())
    return f"{t}|{c}" if c else t


def load(memory_dir: str = DEFAULT_DIR) -> dict:
    """Read the store; a missing or corrupt file is an empty store, never an
    error — memory is an optimisation and must never break an investigation."""
    try:
        with open(_path(memory_dir), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and isinstance(data.get("targets"), dict):
            return data
    except Exception:
        pass
    return {"version": MEMORY_VERSION, "targets": {}}


def save(data: dict, memory_dir: str = DEFAULT_DIR) -> bool:
    try:
        os.makedirs(memory_dir, exist_ok=True)
        tmp = _path(memory_dir) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        os.replace(tmp, _path(memory_dir))    # atomic; no half-written store
        return True
    except Exception:
        return False


def _prune(data: dict) -> None:
    targets = data.get("targets", {})
    if len(targets) <= MAX_ENTRIES:
        return
    ordered = sorted(targets.items(), key=lambda kv: kv[1].get("last_seen", ""))
    for k, _ in ordered[:len(targets) - MAX_ENTRIES]:
        targets.pop(k, None)


# ---- write -----------------------------------------------------------------

def remember(target: str, context: str, deep_state: Optional[dict],
             memory_dir: str = DEFAULT_DIR, flag: str = "auto") -> bool:
    """Store the identities a run confirmed. Returns True when written.

    Only candidates the loop actually corroborated are kept — recording
    rejected namesakes would reintroduce them as noise on the next run.
    """
    if not enabled(flag) or not deep_state:
        return False
    # Never store a placeholder as if it were an identity: "person in photo.jpg" is
    # a description of a picture, and recalling it would warm-start future runs
    # with nonsense.
    from .pipeline import _is_placeholder_subject
    if _is_placeholder_subject(target):
        return False
    from .deepsearch import RESOLVED_OUTCOMES
    _worth_remembering = RESOLVED_OUTCOMES | {"weak"}
    cands = [c for c in (deep_state.get("candidates") or [])
             if c.get("outcome") in _worth_remembering and c.get("evidence")]
    if not cands:
        return False

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data = load(memory_dir)
    k = key_for(target, context)
    prior = data["targets"].get(k, {})
    data["targets"][k] = {
        "target": target,
        "context": context,
        "first_seen": prior.get("first_seen", now),
        "last_seen": now,
        "runs": int(prior.get("runs", 0)) + 1,
        "identities": [{
            "label": c.get("label", ""),
            "role": c.get("role", ""),
            "org": c.get("org", ""),
            "location": c.get("location", ""),
            "context_match": c.get("context_match", 0.0),
            "outcome": c.get("outcome", ""),
            "usernames": (c.get("attributes") or {}).get("usernames", [])[:8],
            "handles": (c.get("attributes") or {}).get("handles", [])[:8],
            "orgs": (c.get("attributes") or {}).get("orgs", [])[:8],
            "urls": [r.get("url", "") for r in (c.get("evidence") or [])[:8]
                     if r.get("url")],
        } for c in cands[:5]],
    }
    _prune(data)
    return save(data, memory_dir)


# ---- read ------------------------------------------------------------------

def recall(target: str, context: str = "", memory_dir: str = DEFAULT_DIR,
           flag: str = "auto") -> Optional[dict]:
    """Return a prior entry for this target, or None.

    Falls back to a context-free match so 'Alex Marsh' still finds an entry
    stored as 'Alex Marsh|ai security industry' — the qualifier may be phrased
    differently from one run to the next.
    """
    if not enabled(flag):
        return None
    data = load(memory_dir)
    targets = data.get("targets", {})
    exact = targets.get(key_for(target, context))
    if exact:
        return exact
    base = key_for(target)
    for k, v in targets.items():
        if k == base or k.startswith(base + "|"):
            return v
    return None


def prior_terms(entry: Optional[dict], limit: int = 6) -> list:
    """Distinguishing terms from a remembered identity, for seeding queries."""
    if not entry:
        return []
    out, seen = [], set()
    for ident in entry.get("identities", []):
        for v in ([ident.get("org"), ident.get("role"), ident.get("location")]
                  + list(ident.get("orgs") or [])
                  + list(ident.get("usernames") or [])
                  + list(ident.get("handles") or [])):
            v = re.sub(r"\s+", " ", str(v or "")).strip()
            if 2 <= len(v) <= 40 and v.lower() not in seen:
                seen.add(v.lower())
                out.append(v)
    return out[:limit]


def summarize(entry: Optional[dict]) -> str:
    """One-line description of a remembered identity, for prompts and logs."""
    if not entry:
        return ""
    parts = []
    for ident in entry.get("identities", [])[:3]:
        bits = [b for b in (ident.get("label"), ident.get("role"),
                            ident.get("org"), ident.get("location")) if b]
        if bits:
            parts.append(" / ".join(bits))
    return "; ".join(parts)


# ---- erase -----------------------------------------------------------------

def forget(target: str, context: str = "", memory_dir: str = DEFAULT_DIR) -> int:
    """Delete entries matching this target. Returns how many were removed.

    Works regardless of the --memory flag: switching recording off must never
    prevent someone from deleting what is already stored.
    """
    data = load(memory_dir)
    targets = data.get("targets", {})
    base = key_for(target, context)
    name_only = key_for(target)
    victims = [k for k in targets
               if k == base or k == name_only or k.startswith(name_only + "|")]
    for k in victims:
        targets.pop(k, None)
    if victims:
        save(data, memory_dir)
    return len(victims)


def forget_all(memory_dir: str = DEFAULT_DIR) -> int:
    """Delete the entire store. Returns how many entries were removed."""
    data = load(memory_dir)
    n = len(data.get("targets", {}))
    data["targets"] = {}
    save(data, memory_dir)
    # remove the file too, so nothing lingers on disk
    try:
        if n or os.path.exists(_path(memory_dir)):
            os.remove(_path(memory_dir))
    except Exception:
        pass
    return n


def entries(memory_dir: str = DEFAULT_DIR) -> list:
    """Everything held, newest first — for --list-memory."""
    data = load(memory_dir)
    return sorted(data.get("targets", {}).values(),
                  key=lambda e: e.get("last_seen", ""), reverse=True)


def describe_store(memory_dir: str = DEFAULT_DIR) -> str:
    rows = entries(memory_dir)
    if not rows:
        return f"  memory is empty ({_path(memory_dir)})"
    out = [f"  {len(rows)} remembered investigation(s) — {_path(memory_dir)}", ""]
    for e in rows:
        out.append(f"  · {e.get('target')}"
                   + (f"  [{e.get('context')}]" if e.get("context") else "")
                   + f"   runs={e.get('runs', 1)}  last={e.get('last_seen', '')}")
        for ident in e.get("identities", []):
            bits = " / ".join(b for b in (ident.get("role"), ident.get("org"),
                                          ident.get("location")) if b)
            out.append(f"      - {ident.get('label', '')}"
                       + (f"  ({bits})" if bits else "")
                       + f"  [{ident.get('outcome', '')}]")
            for u in (ident.get("urls") or [])[:3]:
                out.append(f"          {u}")
    out.append("")
    out.append('  erase: --forget "<target>"   or   --forget-all')
    return "\n".join(out)
