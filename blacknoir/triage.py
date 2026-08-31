"""Inbox triage — recommend which inbound messages to answer first.

Pure read-only analysis of the operator's OWN inbox. It ranks messages by how
much they seem to want a reply; it never sends anything. LLM-ranked when a
provider is available, with a deterministic heuristic fallback.
"""

from __future__ import annotations

import json

from .models import InboxItem

_URGENT = ("urgent", "asap", "immediately", "important", "verify", "verification",
           "security", "password", "payment", "invoice", "overdue", "deadline",
           "action required", "confirm", "suspended", "locked", "expire")
_ENGAGE = ("?", "please", "reply", "respond", "let me know", "waiting", "help",
           "question", "can you", "could you", "follow up")


def _heuristic_score(item: InboxItem, recency_rank: int, total: int) -> tuple[int, str]:
    text = f"{item.subject} {item.body}".lower()
    score, reasons = 0, []
    hits = [w for w in _URGENT if w in text]
    if hits:
        score += 40 + 5 * len(hits)
        reasons.append("urgency terms: " + ", ".join(hits[:3]))
    eng = [w for w in _ENGAGE if w in text]
    if eng:
        score += 15 + 3 * len(eng)
        reasons.append("asks for a reply")
    # recency: newer (lower rank) scores higher
    if total > 1:
        score += int(25 * (total - recency_rank) / total)
        reasons.append("recent" if recency_rank < total / 2 else "older")
    if item.links:
        reasons.append(f"{len(item.links)} link(s) — do NOT open")
    return min(score, 100), "; ".join(reasons) or "no strong signals"


def _heuristic(items: list[InboxItem]) -> list[dict]:
    n = len(items)
    ranked = []
    for i, it in enumerate(items):
        score, reason = _heuristic_score(it, i, n)
        ranked.append({"item": it, "score": score, "reason": reason})
    ranked.sort(key=lambda r: -r["score"])
    return ranked


def triage(items: list[InboxItem], agent=None) -> list[dict]:
    if not items:
        return []
    if agent is not None and getattr(agent, "enabled", False):
        out = _triage_llm(items, agent)
        if out:
            return out
    return _heuristic(items)


def _triage_llm(items: list[InboxItem], agent) -> list[dict]:
    payload = [{"i": i, "from": it.sender[:60], "subject": it.subject[:80],
                "snippet": it.body[:200], "date": it.date}
               for i, it in enumerate(items)]
    prompt = (
        "Below is the operator's OWN inbox (JSON). Rank which messages they "
        "should respond to first. Consider urgency, sender, and whether a reply "
        "is expected. Respond ONLY as JSON: "
        '[{"i":<index>,"score":0-100,"reason":"short"}], most urgent first. '
        "Do not invent messages.\n\n" + json.dumps(payload)[:6000])
    out = agent.llm.complete_text(
        "You triage an inbox. Output strict JSON only.", prompt, 1200)
    if not out:
        return []
    try:
        data = json.loads(out[out.find("["):out.rfind("]") + 1])
    except Exception:
        return []
    ranked = []
    for r in data:
        idx = r.get("i")
        if isinstance(idx, int) and 0 <= idx < len(items):
            ranked.append({"item": items[idx],
                           "score": int(r.get("score", 0)),
                           "reason": str(r.get("reason", ""))[:200]})
    return ranked or []
