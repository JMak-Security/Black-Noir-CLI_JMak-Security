"""Minimal .env loader (no third-party dependency).

Reads KEY=VALUE lines from a .env file and injects them into os.environ,
without overwriting variables already set in the real environment (so an
explicit `export` or shell var always wins over the file).
"""

from __future__ import annotations

import os
from pathlib import Path


def load_dotenv(path: str = ".env") -> int:
    p = Path(path)
    if not p.exists():
        return 0
    loaded = 0
    for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val
            loaded += 1
    return loaded
