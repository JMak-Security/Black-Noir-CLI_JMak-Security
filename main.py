#!/usr/bin/env python3
"""Black Noir CLI entrypoint.

Usage:
    python main.py <target|instruction> [options]
    python main.py --chat
    python main.py --list-sources
    python main.py --help
"""
def _apply_max_env() -> None:
    """MAX-mode budget boost, applied BEFORE importing the package.

    `deepsearch` and `config` read their query/budget knobs at import time, so
    `--max` (or BLACKNOIR_MAX=1) has to raise them here, before any import. Each
    value is only a default — an explicit env var you set still wins.
    """
    import os
    import sys
    if not (any(a == "--max" for a in sys.argv) or os.environ.get("BLACKNOIR_MAX")):
        return
    boosted = {
        "BLACKNOIR_MAX_QUERIES": "12",        # per-engine query variations
        "BLACKNOIR_MAX_RESULTS": "25",        # kept per source per query
        "BLACKNOIR_MAX_MERGED": "60",         # merged cap per source
        "BLACKNOIR_DEEP_QUERY_BUDGET": "120",  # hard ceiling per deep run
        "BLACKNOIR_DEEP_RECON_QUERIES": "8",
        "BLACKNOIR_DEEP_ROUND_QUERIES": "5",
        "BLACKNOIR_DEEP_MAX_DEPTH": "5",
        "BLACKNOIR_DEEP_MAX_CANDIDATES": "5",
        "BLACKNOIR_DEEP_REFLECT_QUERIES": "8",
        "BLACKNOIR_DEEP_WALL_DORKS": "10",
    }
    for key, val in boosted.items():
        os.environ.setdefault(key, val)


_apply_max_env()

from blacknoir.cli import main

if __name__ == "__main__":
    try:
        rc = main()
    except Exception as exc:  # keep the window open on a hard error (double-click)
        import traceback
        traceback.print_exc()
        try:
            from blacknoir.cli import _pause_if_double_click
            _pause_if_double_click()
        except Exception:
            pass
        rc = 1
    raise SystemExit(rc)
