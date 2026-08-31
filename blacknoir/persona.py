"""Research-identity (persona) vault + opsec guard.

A *persona* is a burner identity the operator creates and runs themselves — a
throwaway email, a burner Telegram, etc. — kept separate from their real
identity so OSINT never traces back to them. This module only **documents and
tracks** those identities; it never creates or operates an account.

Nothing sensitive is stored: only references (usernames, emails, the path to a
session file, notes). Real secrets (passwords, API keys, app-passwords, tokens)
live in `.env`, never here. The vault file is gitignored.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

from .preflight import vpn_active

VAULT_PATH = "personas/vault.json"


@dataclass
class Persona:
    name: str
    created: str = ""
    accounts: list[dict] = field(default_factory=list)  # {platform,username,email,session_file,notes}
    notes: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Persona":
        return Persona(
            name=d.get("name", ""), created=d.get("created", ""),
            accounts=list(d.get("accounts", [])), notes=d.get("notes", ""),
            tags=list(d.get("tags", [])))


class PersonaVault:
    def __init__(self, path: str = VAULT_PATH) -> None:
        self.path = Path(path)
        self.personas: dict[str, Persona] = {}
        self.load()

    # -- persistence ---------------------------------------------------------

    def load(self) -> None:
        self.personas = {}
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                for d in data.get("personas", []):
                    p = Persona.from_dict(d)
                    if p.name:
                        self.personas[p.name.lower()] = p
            except Exception:
                pass

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"personas": [p.to_dict() for p in self.personas.values()]}
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    # -- CRUD ----------------------------------------------------------------

    def list(self) -> list[Persona]:
        return list(self.personas.values())

    def get(self, name: str) -> Persona | None:
        return self.personas.get((name or "").lower())

    def add(self, name: str) -> Persona:
        existing = self.get(name)
        if existing:
            return existing
        p = Persona(name=name, created=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.personas[name.lower()] = p
        self.save()
        return p

    def remove(self, name: str) -> bool:
        key = (name or "").lower()
        if key in self.personas:
            del self.personas[key]
            self.save()
            return True
        return False

    def add_account(self, name: str, platform: str, username: str = "",
                    email: str = "", session_file: str = "",
                    notes: str = "") -> Persona | None:
        p = self.get(name)
        if not p:
            return None
        p.accounts.append({
            "platform": platform, "username": username, "email": email,
            "session_file": session_file, "notes": notes})
        self.save()
        return p


# --- opsec guard ------------------------------------------------------------

def opsec_check(active_persona: str | None, live: bool,
                surfaces: list[str] | None = None,
                vault: PersonaVault | None = None) -> list[str]:
    """Advisory warnings before a live action might leak the real identity."""
    warnings: list[str] = []
    if not live:
        return warnings
    active, name = vpn_active()
    if not active:
        warnings.append("VPN: no active tunnel — a live search egresses from "
                        "your REAL IP. Connect a VPN or use --preflight enforce.")
    if not active_persona:
        warnings.append("Persona: none selected — you may be acting under your "
                        "real identity. Use --persona <name> or /persona use.")
    elif vault is not None and not vault.get(active_persona):
        warnings.append(f"Persona: '{active_persona}' is not in the vault "
                        "(create it with /persona new).")
    return warnings
