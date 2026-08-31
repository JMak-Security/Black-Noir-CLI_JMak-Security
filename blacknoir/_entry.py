"""Console-script entry point.

`--max` raises the query/budget ceilings, but `deepsearch` and `config` read
those knobs at IMPORT time — so the boost has to be applied before the package
is imported, not inside `cli.main()`. `main.py` does this for source checkouts;
this module does the same for the installed `blacknoir` command, so both paths
behave identically.

Keep the import of `blacknoir.cli` inside `run()`. Hoisting it to module level
would import the package before `_apply_max_env()` runs and silently make
`--max` a no-op.
"""

from __future__ import annotations

import os
import sys

# Each value is only a DEFAULT: an env var the operator set explicitly wins,
# which is why this uses setdefault rather than assignment.
_MAX_DEFAULTS = {
    "BLACKNOIR_MAX_QUERIES": "12",          # per-engine query variations
    "BLACKNOIR_MAX_RESULTS": "25",          # kept per source per query
    "BLACKNOIR_MAX_MERGED": "60",           # merged cap per source
    "BLACKNOIR_DEEP_QUERY_BUDGET": "120",   # hard ceiling per deep run
    "BLACKNOIR_DEEP_RECON_QUERIES": "8",
    "BLACKNOIR_DEEP_ROUND_QUERIES": "5",
    "BLACKNOIR_DEEP_MAX_DEPTH": "5",
    "BLACKNOIR_DEEP_MAX_CANDIDATES": "5",
    "BLACKNOIR_DEEP_REFLECT_QUERIES": "8",
    "BLACKNOIR_DEEP_WALL_DORKS": "10",
}


def _apply_max_env() -> None:
    """Raise the budget ceilings when --max (or BLACKNOIR_MAX) is requested."""
    if not (any(a == "--max" for a in sys.argv) or os.environ.get("BLACKNOIR_MAX")):
        return
    for key, val in _MAX_DEFAULTS.items():
        os.environ.setdefault(key, val)


def run() -> int:
    """Entry point for the `blacknoir` console script."""
    _apply_max_env()
    from blacknoir.cli import main          # imported AFTER the env boost
    try:
        return main()
    except KeyboardInterrupt:
        print("\naborted.", file=sys.stderr)
        return 130


def main() -> None:
    """Wrapper that turns the return code into a process exit."""
    raise SystemExit(run())


if __name__ == "__main__":
    main()
