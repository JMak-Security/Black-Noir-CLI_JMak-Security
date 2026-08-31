"""Manual runbook export.

Sources that Black Noir cannot (or is configured not to) auto-run — Tor-only
engines and external toolkits — are turned into a copy-paste checklist: the
exact search terms, the onion links found, and the commands/steps to run each
tool yourself. Run them, then drop the output into input/ for correlation.

Nothing here contacts an onion service; it only writes instructions.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .connectors import external_cmd_for
from .models import Investigation

# manual / onion-bound sources the tool hands back to the operator
_MANUAL = {
    "torch": ("Torch", "Tor-only onion search engine (no clearnet API)."),
    "darkweb_scraper": ("dark-web-scraper", "local Tor scraping tool."),
    "telepathy": ("Telepathy", "Telegram OSINT toolkit (clearnet, separate tool)."),
}


def render_runbook(inv: Investigation, output_dir: str) -> str:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    slug = "".join(c if c.isalnum() else "_" for c in inv.target)[:40]
    path = out / f"runbook_{slug}_{stamp}.md"

    queries = inv.plan.get("queries") or [inv.target]
    L: list[str] = []
    L.append(f"# Black Noir — Manual Runbook")
    L.append(f"**Subject:** {inv.target}  ·  generated {stamp}\n")
    L.append("These steps cover sources Black Noir does **not** auto-run (Tor-only "
             "or external tools). Run them yourself in a safe, isolated, VPN-backed "
             "environment, then drop any output into `input/` and re-run to "
             "correlate.\n")

    L.append("## Search terms")
    for q in queries:
        L.append(f"- `{q}`")
    L.append("")

    # target-type pivot toolkit — ready-to-open OSINT tools per type
    from .pivots import pivot_toolkit
    toolkit = pivot_toolkit(inv.target, inv.target_type, inv.entities)
    if toolkit:
        L.append("## Pivot toolkit (open in your browser)")
        L.append("_Type-appropriate OSINT tools for this target. Black Noir does "
                 "not open these — you do, manually._\n")
        for kind, tools in toolkit.items():
            L.append(f"**{kind}**")
            for label, url in tools:
                L.append(f"- {label}: {url}")
            L.append("")

    # per manual source present in this run
    present = {r.source for r in inv.runs}
    for key, (label, desc) in _MANUAL.items():
        if key not in present:
            continue
        L.append(f"## {label}")
        L.append(f"_{desc}_\n")
        wired = external_cmd_for(key)
        if wired:
            L.append(f"Wired via env — Black Noir runs on `--live`:\n\n```\n{wired}\n```\n")
        if key == "torch":
            L.append("1. Open **Tor Browser**.")
            L.append("2. Find Torch's current `.onion` via a trusted index "
                     "(e.g. search 'Torch' on https://ahmia.fi) — avoid random clones.")
            L.append("3. Search each term above. Review results **inside Tor only**.")
        elif key == "telepathy":
            L.append("```bash")
            L.append("pip install telepathy         # one-time")
            L.append("# get API id/hash (free): https://my.telegram.org")
            L.append(f"telepathy -u {inv.target}     # username   (or -c <channel>)")
            L.append("```")
            L.append("Then copy telepathy's output files into `input/`.")
            L.append("\n_To automate: set `TELEPATHY_CMD=\"telepathy -u {q}\"` in `.env`._")
        elif key == "darkweb_scraper":
            L.append("Run your local Tor-based scraper with the terms above, e.g.:")
            L.append("```bash\n<your-scraper> --query \"" + queries[0] + "\"\n```")
            L.append("_To automate: set `DARKWEB_SCRAPER_CMD` in `.env`._")
        L.append("")

    # onion links surfaced by clearnet indexes (Ahmia etc.) — review in Tor
    onions = [r for r in inv.all_results if r.is_onion]
    if onions:
        L.append("## Onion links found (open ONLY in Tor Browser)")
        L.append("_Black Noir captured these as text from clearnet indexes; it did "
                 "not visit them._\n")
        seen = set()
        for r in onions:
            u = r.url or r.title
            if u in seen:
                continue
            seen.add(u)
            L.append(f"- {r.title[:80]}  \n  `{u}`")
        L.append("")

    # reverse-image manual uploads
    rev = [r for run in inv.runs if run.source == "reverse_prepared"
           for r in run.results]
    face = [r for run in inv.runs if run.label.startswith("Face search")
            for r in run.results]
    if rev or face:
        L.append("## Reverse-image (manual upload)")
        for r in rev + face:
            L.append(f"- {r.title}: {r.url}")
        L.append("")

    # breach note
    if any(r.source == "hibp" and "needs HIBP_API_KEY" in (r.detail or "")
           for r in inv.runs):
        L.append("## Breach (per-account)")
        L.append("HIBP per-account email lookups need `HIBP_API_KEY` "
                 "(domain lookups already ran keyless).\n")

    path.write_text("\n".join(L), encoding="utf-8")
    return str(path)
