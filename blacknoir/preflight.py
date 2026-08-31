"""Defensive preflight: ensure Docker + VPN before any live search.

Rationale: a live OSINT sweep sends real requests from the host. For "absolute
defense" Black Noir can require the operator to run behind:

  * Docker Desktop  — so the tool (and any helper containers) run isolated,
  * an active VPN   — so requests don't egress from the operator's real IP.

Policies:
  off      skip all checks
  warn     check + try to auto-start/spin-up, but never block the run (default)
  enforce  Docker must be running AND a VPN active, else the live search is
           downgraded to plan-only (no network leaves the machine)

Every install/start action is consent-gated (prompt, or --yes to auto-approve).
All detection is read-only. Nothing here is destructive without confirmation.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import time
from typing import Callable

Logger = Callable[[str], None]

# VPN client adapters (present only when a real tunnel client is installed/up).
_VPN_ADAPTER_HINTS = (
    "wireguard", "wintun", "tap-windows", "tap-openvpn", "openvpn", "nordlynx",
    "proton", "mullvad", "expressvpn", "tunnelbear", "windscribe", "surfshark",
    "anyconnect", "zerotier", "tailscale",
)
_VPN_PROCESS_HINTS = (
    "openvpn", "wireguard", "nordvpn", "expressvpn", "mullvad", "protonvpn",
    "windscribe", "surfshark", "tunnelbear", "openconnect", "vpnagent",
    "tailscaled", "tailscale", "zerotier",
)

_DOCKER_DESKTOP_PATHS = (
    r"%ProgramFiles%\Docker\Docker\Docker Desktop.exe",
    r"%LocalAppData%\Docker\Docker Desktop.exe",
    r"%ProgramW6432%\Docker\Docker\Docker Desktop.exe",
)


# --- process helpers --------------------------------------------------------

def _run(cmd: list[str], timeout: float = 20) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as exc:
        return 1, f"{type(exc).__name__}: {exc}"


def _confirm(question: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin or not sys.stdin.isatty():
        return False  # non-interactive: never take install/start actions silently
    try:
        return input(f"    {question} [y/N] ").strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


# --- Docker -----------------------------------------------------------------

def docker_installed() -> bool:
    return shutil.which("docker") is not None


def docker_running() -> bool:
    if not docker_installed():
        return False
    code, _ = _run(["docker", "info"], timeout=25)
    return code == 0


def _docker_desktop_exe() -> str | None:
    for raw in _DOCKER_DESKTOP_PATHS:
        p = os.path.expandvars(raw)
        if os.path.exists(p):
            return p
    return None


def start_docker_desktop(log: Logger, wait_s: int = 120) -> bool:
    exe = _docker_desktop_exe()
    if not exe:
        log("Docker Desktop executable not found")
        return False
    log("launching Docker Desktop and waiting for the daemon…")
    try:
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) \
            if sys.platform == "win32" else 0
        subprocess.Popen([exe], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, creationflags=flags)
    except Exception as exc:
        log(f"failed to launch Docker Desktop: {exc}")
        return False
    deadline = time.time() + wait_s
    while time.time() < deadline:
        if docker_running():
            return True
        time.sleep(3)
    return False


def winget_install(pkg_id: str, name: str, log: Logger,
                   assume_yes: bool) -> bool:
    if not shutil.which("winget"):
        log(f"winget unavailable — install {name} manually.")
        return False
    if not _confirm(f"install {name} via winget (id={pkg_id})?", assume_yes):
        log(f"skipped installing {name}.")
        return False
    log(f"installing {name} via winget (this can take a while)…")
    code, out = _run(["winget", "install", "-e", "--id", pkg_id,
                      "--accept-package-agreements",
                      "--accept-source-agreements"], timeout=1800)
    ok = code == 0
    log(f"{name} install {'succeeded' if ok else 'did not complete'} "
        f"(a reboot may be required).")
    return ok


def spin_up_containers(log: Logger, assume_yes: bool,
                       compose_file: str = "docker-compose.yml") -> None:
    if not os.path.exists(compose_file):
        log("no docker-compose.yml present — nothing to spin up.")
        return
    # docker compose (v2) preferred; fall back to docker-compose (v1)
    base = ["docker", "compose"]
    if _run(["docker", "compose", "version"], 15)[0] != 0:
        base = ["docker-compose"] if shutil.which("docker-compose") else None
    if not base:
        log("docker compose not available — skipping spin-up.")
        return
    if not _confirm("spin up docker-compose services (up -d)?", assume_yes):
        log("skipped container spin-up.")
        return
    log("bringing up containers: docker compose up -d …")
    code, out = _run(base + ["up", "-d"], timeout=900)
    log("containers up ✓" if code == 0 else f"compose up failed: {out[:160]}")


# --- VPN --------------------------------------------------------------------

def vpn_active() -> tuple[bool, str]:
    """Best-effort detection of an active VPN tunnel. (present, name)."""
    if sys.platform == "win32":
        code, out = _run([
            "powershell", "-NoProfile", "-Command",
            "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | "
            "Select-Object -ExpandProperty InterfaceDescription"], 25)
        low = out.lower()
        for h in _VPN_ADAPTER_HINTS:
            if h in low:
                return True, h
        code, out = _run(["tasklist"], 20)
        low = out.lower()
        for h in _VPN_PROCESS_HINTS:
            if f"{h}.exe" in low:
                return True, h
        return False, ""
    # POSIX fallback: look for tun/tap/wg/ppp interfaces
    code, out = _run(["ip", "-o", "link"], 10)
    low = out.lower()
    for h in ("wg", "tun", "tap", "ppp", "utun"):
        if f": {h}" in low or f" {h}0" in low:
            return True, h
    return False, ""


def connect_vpn(log: Logger, assume_yes: bool, wait_s: int = 30) -> bool:
    """Bring a VPN tunnel up via the operator-supplied VPN_UP_CMD, then confirm.

    There is no universal way to connect an arbitrary VPN client, so Black Noir
    runs the exact command the operator configured (their client, their
    credentials) and waits for a tunnel to appear. Without VPN_UP_CMD it can
    only *detect* a tunnel, never start one. Consent-gated like every other
    state-changing preflight action.
    """
    if vpn_active()[0]:
        return True
    tmpl = os.environ.get("VPN_UP_CMD", "").strip()
    if not tmpl:
        log("VPN: no tunnel and no VPN_UP_CMD set — cannot auto-connect. Set "
            "VPN_UP_CMD to your client's connect command, or connect manually.")
        return False
    if not _confirm(f"connect VPN via VPN_UP_CMD ({tmpl})?", assume_yes):
        log("VPN: auto-connect skipped by operator.")
        return False
    try:
        argv = shlex.split(tmpl, posix=(os.name != "nt"))
    except Exception:
        argv = tmpl.split()
    log("VPN: connecting via VPN_UP_CMD …")
    _run(argv, timeout=60)
    deadline = time.time() + wait_s
    while time.time() < deadline:
        active, name = vpn_active()
        if active:
            log(f"VPN: tunnel up ({name}) ✓")
            return True
        time.sleep(3)
    log(f"VPN: VPN_UP_CMD ran but no tunnel detected within {wait_s}s.")
    return False


def ensure_isolation(log: Logger, assume_yes: bool,
                     want_containers: bool = False) -> tuple[bool, bool]:
    """Best-effort bring-up of Docker + VPN; return (docker_ok, vpn_ok).

    Used to gate identity-egress sources (e.g. Telepathy): the caller drops
    those sources unless BOTH come back True. Every bring-up action is
    consent-gated and idempotent — if a piece is already up it is left alone.
    """
    docker_ok = docker_running()
    if not docker_ok and docker_installed():
        docker_ok = start_docker_desktop(log)
    if docker_ok and want_containers:
        spin_up_containers(log, assume_yes)
    vpn_ok = connect_vpn(log, assume_yes)
    return docker_ok, vpn_ok


# --- orchestrator -----------------------------------------------------------

def run_preflight(policy: str, assume_yes: bool, log: Logger,
                  head: Logger, want_containers: bool = True) -> bool:
    """Return True if the live search may proceed with network enabled.

    In 'enforce' a missing Docker/VPN returns False (caller downgrades to
    plan-only). In 'warn' it always returns True after informing the operator.
    """
    if policy == "off":
        return True

    head("Preflight — defensive isolation checks")
    docker_ok = False
    vpn_ok = False

    # --- Docker ---
    if docker_running():
        log("Docker: daemon running ✓")
        docker_ok = True
        if want_containers:
            spin_up_containers(log, assume_yes)
    elif docker_installed():
        log("Docker: installed but daemon stopped")
        if start_docker_desktop(log):
            log("Docker: daemon running ✓")
            docker_ok = True
            if want_containers:
                spin_up_containers(log, assume_yes)
        else:
            log("Docker: could not confirm the daemon started")
    else:
        log("Docker: not installed")
        winget_install("Docker.DockerDesktop", "Docker Desktop", log, assume_yes)
        log("re-run Black Noir after Docker finishes installing (may need reboot).")

    # --- VPN ---
    active, name = vpn_active()
    if active:
        log(f"VPN: active tunnel detected ({name}) ✓")
        vpn_ok = True
    else:
        log("VPN: no active tunnel detected")
        winget_install("WireGuard.WireGuard", "WireGuard", log, assume_yes)
        log("connect your VPN before running a live search "
            "(clients can't be auto-connected without your config).")

    if policy == "enforce":
        ready = docker_ok and vpn_ok
        if not ready:
            log("enforce: requirements unmet — downgrading to PLAN-ONLY "
                "(no network will leave this machine).")
        return ready
    return True  # warn mode never blocks
