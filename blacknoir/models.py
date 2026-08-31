"""Shared data structures passed between connectors, the agent and the report."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional


@dataclass
class SearchResult:
    source: str                 # source key, e.g. "duckduckgo"
    surface: str                # "public" | "darkweb"
    title: str
    url: str = ""               # kept as text metadata; never auto-fetched
    snippet: str = ""
    is_onion: bool = False
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SourceRun:
    source: str
    label: str
    surface: str
    status: str                 # ok|empty|skipped|error|planned|blocked
    detail: str = ""
    results: list[SearchResult] = field(default_factory=list)
    queries: list[str] = field(default_factory=list)  # variations actually run

    def to_dict(self) -> dict:
        d = asdict(self)
        d["results"] = [r.to_dict() for r in self.results]
        return d


@dataclass
class InboxItem:
    """One inbound message/comment/mention read from a channel (sanitized)."""
    channel: str                # "email" | "telegram" | "instagram" | ...
    sender: str = ""
    subject: str = ""
    date: str = ""
    body: str = ""              # sanitized text only
    links: list[str] = field(default_factory=list)        # inert text, never fetched
    attachments: list[str] = field(default_factory=list)  # names only, never opened
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SendResult:
    ok: bool
    channel: str
    recipient: str
    detail: str = ""
    preview: str = ""


@dataclass
class Entity:
    value: str
    kind: str                   # email|username|domain|onion|btc|phone|ip|name|handle
    first_seen: str = ""        # source key where first observed
    weight: int = 1

    def key(self) -> str:
        return f"{self.kind}:{self.value.lower()}"


@dataclass
class Edge:
    src: str                    # entity.key()
    dst: str                    # entity.key()
    relation: str
    source: str


@dataclass
class Investigation:
    target: str
    target_type: str
    surfaces: list[str]
    started: str
    raw: str = ""                       # the original free-form instruction
    context: str = ""                   # qualifier that disambiguates the subject
                                        # ("AI security industry") — MUST reach
                                        # the query builder, not just the report
    aliases: list[str] = field(default_factory=list)  # other names for the SAME
                                        # subject (native script, romanization,
                                        # legal name) — searched as well, and
                                        # accepted by the relevance filter
    intent: dict = field(default_factory=dict)  # parsed {subject,depth,...}
    input_context: dict = field(default_factory=dict)
    plan: dict = field(default_factory=dict)
    runs: list[SourceRun] = field(default_factory=list)
    entities: list[Entity] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    synthesis: dict = field(default_factory=dict)
    guardrails: dict = field(default_factory=dict)
    persona: str = ""                   # research identity that ran this
    correlation_skipped: int = 0        # results judged not about the target
    deep_search: dict = field(default_factory=dict)  # candidate loop state

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "surfaces": self.surfaces,
            "started": self.started,
            "persona": self.persona,
            "raw": self.raw,
            "context": self.context,
            "aliases": self.aliases,
            "intent": self.intent,
            "input_context": self.input_context,
            "plan": self.plan,
            "runs": [r.to_dict() for r in self.runs],
            "entities": [asdict(e) for e in self.entities],
            "edges": [asdict(e) for e in self.edges],
            "correlation_skipped": self.correlation_skipped,
            "deep_search": self.deep_search,
            "synthesis": self.synthesis,
            "guardrails": self.guardrails,
        }

    @property
    def all_results(self) -> list[SearchResult]:
        out: list[SearchResult] = []
        for run in self.runs:
            out.extend(run.results)
        return out
