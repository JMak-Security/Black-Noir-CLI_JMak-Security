"""Command-line interface for Black Noir."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .config import REGISTRY
from .env import load_dotenv
from .llm import AUTO_ORDER, DEFAULT_PANEL_SIZE
from .pipeline import Console, investigate

BANNER = r"""
  ██████  ██       █████   ██████ ██   ██     ███    ██  ██████  ██ ██████
  ██   ██ ██      ██   ██ ██      ██  ██      ████   ██ ██    ██ ██ ██   ██
  ██████  ██      ███████ ██      █████       ██ ██  ██ ██    ██ ██ ██████
  ██   ██ ██      ██   ██ ██      ██  ██      ██  ██ ██ ██    ██ ██ ██   ██
  ██████  ███████ ██   ██  ██████ ██   ██     ██   ████  ██████  ██ ██   ██
        d e e p - s e a r c h   O S I N T   a g e n t   ·   v%s
""" % __version__


def _list_sources() -> None:
    from .llm import SPECS, LLM
    print("\nAvailable sources:\n")
    for surface in ("public", "darkweb"):
        print(f"  [{surface}]")
        for s in REGISTRY.values():
            if s.surface != surface:
                continue
            avail = "ready " if s.available else s.unavailable_reason
            print(f"    {s.key:<16} {s.label:<20} {s.category:<16} ({avail})")
        print()
    print("  [LLM providers]")
    for name, spec in SPECS.items():
        ready = "ready" if LLM._available(name) else "not configured"
        model = os.environ.get(spec.model_env) or spec.default_model
        kind = "OpenAI-compatible" if spec.kind == "openai" else "native"
        print(f"    {name:<12} {model:<34} {kind:<18} ({ready})")
    print()


def _list_personas() -> None:
    from .persona import PersonaVault
    ps = PersonaVault().list()
    if not ps:
        print("\nNo personas yet. In chat: /persona new <name>\n")
        return
    print("\nPersonas:\n")
    for p in ps:
        print(f"  {p.name}  (created {p.created}, {len(p.accounts)} account(s))")
        for a in p.accounts:
            who = a.get("username") or a.get("email") or ""
            print(f"      - {a.get('platform', '?')}: {who}")
    print()


def _confirm_send(preview: str) -> bool:
    print("\n--- PREVIEW (ONE message) ---\n" + preview
          + "\n-----------------------------")
    try:
        return input("Send this one message? [y/N] ").strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def _do_send(args) -> int:
    from .messenger import get_provider
    spec = args.send
    if "::" not in spec or ":" not in spec.split("::", 1)[0]:
        print("format: --send provider:recipient::message  "
              "(e.g. email:me@example.com::hi)")
        return 2
    head, msg = spec.split("::", 1)
    prov_name, recipient = head.split(":", 1)
    prov = get_provider(prov_name)
    if not prov:
        print(f"unknown provider '{prov_name}' — options: email, telegram, "
              "instagram, facebook, threads")
        return 2
    ok, reason = prov.available()
    if not ok:
        print(f"{prov_name}: {reason}")
        return 2
    res = prov.send(recipient, msg, _confirm_send)
    print(("\033[92m✓\033[0m " if res.ok else "\033[91m✗\033[0m ") + res.detail)
    return 0 if res.ok else 1


def _do_comment(args) -> int:
    from .messenger import get_provider
    spec = args.comment
    if "::" not in spec or ":" not in spec.split("::", 1)[0]:
        print("format: --comment provider:target::text  "
              "(e.g. youtube:dQw4w9WgXcQ::nice video)")
        return 2
    head, text = spec.split("::", 1)
    prov_name, target = head.split(":", 1)
    prov = get_provider(prov_name)
    if not prov:
        print(f"unknown provider '{prov_name}' — comment works on: youtube, "
              "threads, instagram, facebook")
        return 2
    ok, reason = prov.available()
    if not ok:
        print(f"{prov_name}: {reason}")
        return 2
    res = prov.comment(target, text, _confirm_send)
    print(("\033[92m✓\033[0m " if res.ok else "\033[91m✗\033[0m ") + res.detail)
    return 0 if res.ok else 1


def _do_triage(args) -> int:
    from .messenger import get_provider
    from .triage import triage
    from .agent import Agent
    items = []
    for name in ("email", "instagram", "facebook", "threads"):
        prov = get_provider(name)
        if prov and prov.available()[0]:
            items += prov.list_inbox(15)
    if not items:
        print("No readable inbox. Set EMAIL_ADDRESS + EMAIL_APP_PASSWORD "
              "(Gmail App Password), or Meta credentials.")
        return 0
    agent = Agent(provider=args.provider, model=args.model,
                  use_llm=not args.no_llm)
    ranked = triage(items, agent)
    print(f"\nInbox triage — respond first ({agent.label}):\n")
    for i, r in enumerate(ranked, 1):
        it = r["item"]
        print(f"  {i}. [{it.channel}] {it.sender[:38]} — "
              f"{it.subject[:50]}  (score {r['score']})")
        print(f"      why: {r['reason']}")
        if it.links:
            print(f"      links (inert, NOT opened): {len(it.links)}")
    print()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="blacknoir",
        description="Deep-search OSINT AI agent (public + dark-web surfaces).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  blacknoir john.doe@example.com --surface all --live\n"
            "  blacknoir @nightowl --surface darkweb\n"
            "  blacknoir example.com --only duckduckgo,bing,ahmia --live\n"
            "  blacknoir \"This is Jensen Huang, find every public detail\" --live\n"
            "  blacknoir --chat            # interactive Q&A + /search commands\n"
            "  blacknoir --list-sources\n\n"
            "safety: never contacts .onion services, never downloads files,\n"
            "never follows result links — reads search-index metadata only."),
    )
    p.add_argument("target", nargs="?", help="email, username, @handle, name, domain, phone")
    p.add_argument("--surface", choices=["public", "darkweb", "all"],
                   default="all", help="which surface(s) to search (default: all)")
    p.add_argument("--live", action="store_true",
                   help="perform real clearnet requests (default: plan-only, no network)")
    p.add_argument("--provider", choices=["auto"] + AUTO_ORDER, default="auto",
                   help="LLM backend (default: auto — picks the first configured "
                        "provider and fails over to others on repeated errors)")
    p.add_argument("--model", default=None,
                   help="override the model id for the chosen provider")
    p.add_argument("--no-llm", action="store_true",
                   help="force the deterministic heuristic agent (no LLM calls)")
    p.add_argument("--only", metavar="k1,k2",
                   help="restrict to specific source keys (see --list-sources)")
    p.add_argument("--max", dest="max_mode", action="store_true",
                   help="MAX mode — throw everything at ONE target: all "
                        "surfaces, every available source, deep multi-round "
                        "loop, and the biggest query/budget settings. Best for "
                        "'find every leak' runs. Uses more API credits.")
    p.add_argument("--all-sources", action="store_true",
                   help="query EVERY applicable source for the surface(s), not "
                        "just what the planner picks (deep searches do this anyway)")
    p.add_argument("--no-pdf", action="store_true",
                   help="don't also write a PDF report (PDF is on by default)")
    p.add_argument("--no-runbook", action="store_true",
                   help="don't write the manual runbook (Tor/Telepathy steps)")
    p.add_argument("--preflight", choices=["off", "warn", "enforce"],
                   default="warn",
                   help="defensive Docker+VPN check before a live search "
                        "(warn=check & inform; enforce=require both or "
                        "downgrade to plan-only; off=skip). Default: warn")
    p.add_argument("--yes", "-y", action="store_true",
                   help="auto-approve preflight install/start/spin-up actions")
    p.add_argument("--doctor", action="store_true",
                   help="run the Docker+VPN preflight checks and exit")
    p.add_argument("--chat", action="store_true",
                   help="open the interactive chatbot (open questions + "
                        "/search commands). Any target text becomes the first message.")
    p.add_argument("--reverse-image", choices=["auto", "off"], default="auto",
                   help="reverse-image search on input images: SauceNAO/IQDB "
                        "real uploads (live) + prepared Lens/Yandex/TinEye/Bing "
                        "links. Default: auto (runs when images are present)")
    p.add_argument("--enrich", choices=["auto", "off"], default="auto",
                   help="native enrichment of domains/IPs/BTC/handles via "
                        "keyless official APIs (crt.sh, DNS-over-HTTPS, Shodan "
                        "InternetDB, Blockstream, GitHub, Reddit). Live-only, "
                        "JSON reads only. Default: auto")
    p.add_argument("--deep-loop", choices=["auto", "on", "off"], default="auto",
                   help="iterative candidate loop for the public surface: "
                        "recon -> cluster namesakes into candidates -> score "
                        "against your context -> deep-dive each one, going "
                        "more specific until it saturates. Default: auto "
                        "(on for person/name targets, off for domain/email/"
                        "username). 'off' restores the one-shot sweep")
    p.add_argument("--memory", choices=["auto", "off"], default="auto",
                   help="remember identities confirmed by past runs and use "
                        "them to warm-start the next search on the same "
                        "target. Stored LOCALLY only, in memory/. "
                        "Default: auto. 'off' records nothing")
    p.add_argument("--multi-agent", choices=["on", "off"], default="on",
                   help="run EVERY configured AI provider in parallel: they "
                        "plan the search (queries unioned for wider recall) AND "
                        "vote on the search itself — which results are the same "
                        "person, which belong to a candidate (default: on). "
                        "Ollama is excluded unless BLACKNOIR_PANEL_OLLAMA=1. "
                        "Needs 2+ keyed providers.")
    p.add_argument("--panel-size", default=None, metavar="N|all",
                   help=f"how many AI models plan AND judge each search, "
                        f"INCLUDING the primary (default: {DEFAULT_PANEL_SIZE}). "
                        f"'all' uses every available provider. Also set via "
                        f"BLACKNOIR_PANEL_SIZE.")
    p.add_argument("--list-memory", action="store_true",
                   help="print everything held in memory, in full, and exit")
    p.add_argument("--forget", metavar="TARGET", default=None,
                   help='permanently erase remembered data for a target, '
                        'e.g. --forget "Jane Doe". Works even with --memory off')
    p.add_argument("--forget-all", action="store_true",
                   help="permanently erase the entire memory store and delete "
                        "the file")
    p.add_argument("--input-dir", default="input", help="context folder (default: input)")
    p.add_argument("--output-dir", default="output", help="report folder (default: output)")
    p.add_argument("--quiet", action="store_true", help="suppress progress output")
    p.add_argument("--list-sources", action="store_true", help="list sources and exit")
    p.add_argument("--persona", default=None, metavar="NAME",
                   help="active research identity for this run (opsec + report)")
    p.add_argument("--list-personas", action="store_true",
                   help="list saved personas and exit")
    p.add_argument("--send", metavar="PROV:RCPT::MSG",
                   help="send ONE message, e.g. email:me@x.com::hi — previews + asks y/N")
    p.add_argument("--comment", metavar="PROV:TARGET::TEXT",
                   help="post ONE comment, e.g. youtube:VIDEOID::nice — previews + y/N")
    p.add_argument("--triage", action="store_true",
                   help="rank your inbox (who to answer first) and exit")
    p.add_argument("--check-password", action="store_true",
                   help="self-audit: check ONE of your own passwords against "
                        "Have I Been Pwned's breach corpus and exit. Prompts "
                        "without echo; uses k-anonymity, so only the first 5 "
                        "characters of the SHA-1 hash are ever sent — the "
                        "password never leaves this machine. Needs --live.")
    p.add_argument("--version", action="version", version=f"Black Noir {__version__}")
    return p


def _do_check_password(args) -> int:
    """Self-audit one password against the Pwned Passwords corpus."""
    import getpass

    from .guardrails import Guardrails
    from .http import Fetcher
    from .selfaudit import check_password_pwned

    console = Console(quiet=args.quiet)
    print(f"\033[91m{BANNER}\033[0m")
    if not args.live:
        console.step("--check-password needs --live (it makes one HTTPS call).")
        return 2
    try:
        # getpass keeps it off the screen, out of shell history, and out of the
        # process list — none of which would be true for a --password flag.
        pw = getpass.getpass("  password to check (not echoed, never stored): ")
    except (EOFError, KeyboardInterrupt):
        console.line("")
        return 1
    if not pw:
        console.step("nothing entered.")
        return 1

    guard = Guardrails()
    result = check_password_pwned(pw, Fetcher(guard, live=True))
    del pw  # drop the plaintext as soon as the hash prefix has been sent

    console.line("")
    status = result.get("status")
    if status == "pwned":
        console.head("\033[91mCOMPROMISED\033[0m")
    elif status == "clean":
        console.head("\033[92mnot found in any indexed breach\033[0m")
    else:
        console.head(str(status))
    console.step(result.get("detail", ""))
    console.line("")
    console.step("k-anonymity: only the first 5 characters of the SHA-1 hash "
                 "were sent; the password itself never left this machine.")
    return 0


def _sole_console_process() -> bool:
    """True when we're the only process in the console — i.e. launched by a
    double-click from Explorer rather than from an existing terminal."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        arr = (ctypes.c_uint * 3)()
        n = ctypes.windll.kernel32.GetConsoleProcessList(arr, 3)
        return n <= 1
    except Exception:
        return False


def _pause_if_double_click() -> None:
    if _sole_console_process():
        try:
            input("\nPress Enter to close… (tip: run me from a terminal, "
                  "or use the 'Black Noir (chat).bat' launcher)")
        except Exception:
            pass


def _force_utf8() -> None:
    # Windows terminals default to legacy codepages (cp950/cp1252) that cannot
    # encode the box-drawing / status glyphs. Reconfigure so output never crashes.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore
        except Exception:
            pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8()
    load_dotenv()  # pull provider keys/models from .env if present
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_sources:
        _list_sources()
        return 0

    if args.list_personas:
        _list_personas()
        return 0

    # Memory inspection/erasure runs before anything else and never needs a
    # target — you must always be able to see and delete what is stored.
    if args.list_memory:
        from . import memory as _mem
        print(_mem.describe_store())
        return 0

    if args.forget_all:
        from . import memory as _mem
        n = _mem.forget_all()
        print(f"  erased {n} remembered investigation(s); memory file deleted.")
        return 0

    if args.forget:
        from . import memory as _mem
        n = _mem.forget(args.forget)
        print(f"  erased {n} entr{'y' if n == 1 else 'ies'} for "
              f"{args.forget!r}." if n else
              f"  nothing stored for {args.forget!r}.")
        return 0

    if args.send:
        return _do_send(args)

    if args.comment:
        return _do_comment(args)

    if args.triage:
        return _do_triage(args)

    if args.check_password:
        return _do_check_password(args)

    if args.doctor:
        from .preflight import run_preflight
        console = Console(quiet=False)
        print(f"\033[91m{BANNER}\033[0m")
        ready = run_preflight("warn", args.yes,
                              log=lambda m: console.step(m),
                              head=lambda m: console.head(m))
        console.line("")
        console.step("doctor complete — use --preflight enforce to hard-gate "
                     "live searches on Docker+VPN.")
        return 0

    if args.chat:
        from .chat import start_chat
        print(f"\033[91m{BANNER}\033[0m")
        return start_chat(
            provider=args.provider, model=args.model, use_llm=not args.no_llm,
            surfaces=args.surface, live=(True if args.live else None),
            input_dir=args.input_dir, output_dir=args.output_dir,
            preflight=args.preflight, assume_yes=args.yes,
            reverse_image=args.reverse_image, first_message=args.target)

    if not args.target:
        print(BANNER)
        parser.print_help()
        _pause_if_double_click()
        return 0

    if not args.quiet:
        print(f"\033[91m{BANNER}\033[0m")

    # MAX mode bundles the "spend everything on one target" settings. It only
    # RAISES coverage, so it overrides the individual flags rather than merging.
    # (The per-engine query/budget knobs are boosted even earlier, in main.py,
    # because deepsearch reads those env vars at import time.)
    if getattr(args, "max_mode", False):
        args.surface = "all"
        args.all_sources = True
        args.deep_loop = "on"
        args.enrich = "auto"
        args.reverse_image = "auto"
        args.multi_agent = "on"
        if not args.panel_size:
            args.panel_size = "all"

    surfaces = ["public", "darkweb"] if args.surface == "all" else [args.surface]
    only = [x.strip() for x in args.only.split(",")] if args.only else None
    console = Console(quiet=args.quiet)

    Path(args.output_dir).mkdir(parents=True, exist_ok=True)
    Path(args.input_dir).mkdir(parents=True, exist_ok=True)

    try:
        investigate(
            target=args.target, surfaces=surfaces,
            input_dir=args.input_dir, output_dir=args.output_dir,
            live=args.live, use_llm=not args.no_llm, only=only, console=console,
            provider=args.provider, model=args.model,
            preflight=args.preflight, assume_yes=args.yes,
            reverse_image=args.reverse_image,
            all_sources=args.all_sources, make_pdf=not args.no_pdf,
            make_runbook=not args.no_runbook, enrich=args.enrich,
            deep_loop=args.deep_loop, memory_flag=args.memory,
            multi_agent=args.multi_agent != "off",
            panel_size=args.panel_size,
            active_persona=args.persona,
            max_mode=getattr(args, "max_mode", False),
        )
    except KeyboardInterrupt:
        print("\naborted.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
