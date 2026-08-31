"""PDF report generation (pure-Python via fpdf2).

Produces a clean, printable OSINT report — subject/intent, a stat summary, the
analyst synthesis, per-source findings, the correlated entities, the input
analysis, and the guardrail audit. Best-effort: if fpdf2 is unavailable, the
caller simply skips PDF and keeps the HTML/JSON reports.

fpdf2 core fonts are latin-1, so text is sanitised to stay dependency-free.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .models import Investigation

import warnings

try:
    warnings.filterwarnings("ignore", message=".*Pillow.*")  # we add no images
    from fpdf import FPDF  # fpdf2
    _HAS_FPDF = True
except Exception:
    FPDF = object  # type: ignore
    _HAS_FPDF = False

INK = (20, 22, 30)
RED = (200, 45, 55)
MUT = (120, 125, 140)
LINE = (210, 213, 222)


def _s(text) -> str:
    """Sanitise to latin-1 (fpdf core-font safe)."""
    return str(text).encode("latin-1", "replace").decode("latin-1")


class _Report(FPDF):
    def header(self):
        self.set_fill_color(*INK)
        self.rect(0, 0, self.w, 20, "F")
        self.set_xy(10, 5)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 15)
        self.cell(0, 10, "BLACK NOIR  -  OSINT Report", 0, 0, "L")
        self.set_font("Helvetica", "", 8)
        self.set_text_color(230, 120, 125)
        self.cell(0, 10, "deep-search OSINT agent v1.0   ", 0, 1, "R")
        self.set_y(24)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(*MUT)
        self.cell(0, 8, _s("Index metadata only - no onion service contacted - "
                           "nothing downloaded. Public-source OSINT. "
                           f"Page {self.page_no()}"), 0, 0, "C")

    # -- building blocks -----------------------------------------------------

    def _avail(self) -> float:
        return self.w - self.get_x() - self.r_margin

    def para(self, text, size=9, style="", color=INK, indent=0.0):
        """A left-aligned wrapped paragraph that always starts at the margin."""
        self.set_x(self.l_margin + indent)
        self.set_font("Helvetica", style, size)
        self.set_text_color(*color)
        # align="L" — never justify, or long URLs stretch the spaces on the
        # preceding words across the whole page width.
        self.multi_cell(self._avail(), 5.5, _s(text), align="L")
        self.set_x(self.l_margin)

    def h2(self, title):
        self.ln(2)
        self.set_x(self.l_margin)
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(*RED)
        self.cell(0, 8, _s(title), 0, 1)
        self.set_draw_color(*LINE)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(2)
        self.set_text_color(*INK)

    def kv(self, key, val):
        self.set_x(self.l_margin)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*MUT)
        self.cell(38, 6, _s(key), 0, 0)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*INK)
        self.multi_cell(self._avail(), 6, _s(val), align="L")
        self.set_x(self.l_margin)

    def bullets(self, items):
        if not items:
            self.para("(none)", color=MUT, indent=3)
            return
        for it in items:
            self.para(f"- {it}", indent=3)


def render_pdf(inv: Investigation, output_dir: str) -> str | None:
    if not _HAS_FPDF:
        return None
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    slug = "".join(c if c.isalnum() else "_" for c in inv.target)[:40]
    path = out / f"report_{slug}_{stamp}.pdf"

    pdf = _Report()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    s = inv.synthesis
    # --- summary ---
    pdf.h2("Investigation")
    pdf.kv("Subject", inv.target)
    if inv.raw and inv.raw.strip().lower() != inv.target.strip().lower():
        pdf.kv("Instruction", inv.raw)
    pdf.kv("Type / depth", f"{inv.target_type} / {inv.plan.get('depth','normal')}")
    pdf.kv("Surfaces", ", ".join(inv.surfaces))
    if inv.persona:
        pdf.kv("Research identity", inv.persona)
    pdf.kv("Agent", inv.plan.get("engine", "heuristic"))
    pdf.kv("Started", inv.started)
    pdf.kv("Confidence", str(s.get("confidence", "?")).upper())
    ok = sum(1 for r in inv.runs if r.status == "ok")
    pdf.kv("Coverage", f"{len(inv.runs)} sources queried, {ok} returned data, "
           f"{len(inv.all_results)} results, {len(inv.entities)} entities")

    # --- synthesis ---
    pdf.h2("Analyst synthesis")
    pdf.para(s.get("summary", ""))
    pdf.ln(1)
    pdf.para("Key findings", style="B"); pdf.bullets(s.get("key_findings", []))
    pdf.para("Pivots", style="B"); pdf.bullets(s.get("pivots", []))
    pdf.para("Next steps", style="B"); pdf.bullets(s.get("next_steps", []))
    if s.get("risk_notes"):
        pdf.para("Risk notes", style="B"); pdf.bullets(s.get("risk_notes", []))

    # --- sources & findings ---
    pdf.h2("Sources & findings")
    for run in sorted(inv.runs, key=lambda r: (r.surface, r.source)):
        pdf.para(f"[{run.surface}] {run.label} - {run.status} "
                 f"({len(run.results)} result(s))", style="B")
        if run.detail:
            pdf.para(run.detail, size=8, style="I", color=MUT, indent=3)
        for r in run.results[:8]:
            onion = " [onion]" if r.is_onion else ""
            pdf.para(f"- {r.title}{onion}", size=8, indent=3)
            if r.url:
                pdf.para(r.url, size=8, color=(60, 90, 160), indent=6)
            if r.snippet:
                pdf.para(r.snippet[:220], size=8, color=MUT, indent=6)
        pdf.ln(1)

    # --- entities ---
    pdf.h2("Correlated entities")
    for e in sorted(inv.entities, key=lambda e: -e.weight):
        pdf.para(f"- {e.kind:9} {e.value}  (weight {e.weight})", size=9, indent=3)

    # --- input analysis ---
    if inv.input_context.get("images") or inv.input_context.get("notes"):
        pdf.h2("Input analysis")
        for img in inv.input_context.get("images", []):
            pdf.para(f"Image: {img['name']} [{img.get('subject_type','?')}]", style="B")
            pdf.para(img.get("analysis", "")[:800], size=8, color=MUT, indent=3)

    # --- guardrails ---
    pdf.h2("Guardrail audit")
    g = inv.guardrails
    pdf.para(f"Allowed: {g.get('allowed',0)}   Blocked: {g.get('blocked',0)}   "
             f"Image uploads: {g.get('uploads',0)}   Total: {g.get('total',0)}")
    for b in g.get("blocked_urls", [])[:20]:
        pdf.para(f"blocked ({b['reason']}): {b['url']}", size=8, color=MUT, indent=3)

    pdf.output(str(path))
    return str(path)
