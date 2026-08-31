"""Render an investigation into a self-contained visual HTML report + JSON.

The HTML embeds an interactive force-directed entity graph (vanilla JS on a
<canvas>, no external libraries), a source-by-source findings breakdown, a
timeline, the input-folder analysis, and the guardrail audit log. Everything is
inline so the report opens offline from the output/ folder.
"""

from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path

from .models import Investigation

_KIND_COLOR = {
    "target": "#ff3b47", "email": "#4fc3f7", "username": "#ffb74d",
    "domain": "#81c784", "onion": "#ba68c8", "btc": "#fff176",
    "phone": "#4dd0e1", "ip": "#f06292", "handle": "#9575cd", "name": "#a1887f",
}


def _esc(s: str) -> str:
    return html.escape(str(s), quote=True)


def _ev_link(url: str, name: str = "") -> str:
    """Render an evidence URL as a clickable link that jumps to the name.

    A finding usually lives on a long page (a school roster, a directory) where
    the target is one line among hundreds. A plain link drops the reader at the
    top to hunt for it. Appending a text-fragment (`#:~:text=<name>`) makes a
    modern browser scroll to and highlight the first occurrence on click, so the
    link lands precisely on the mention. Added only when the URL has no fragment
    of its own, and the raw URL is still shown as the visible text.
    """
    if not url:
        return ""
    from urllib.parse import quote
    href = url
    if name and "#" not in url:
        href = f"{url}#:~:text={quote(name.strip())}"
    return (f'<div class="u"><a href="{_esc(href)}" target="_blank" '
            f'rel="noopener noreferrer">{_esc(url)}</a></div>')


def _graph_data(inv: Investigation) -> dict:
    nodes = [{
        "id": e.key(), "label": e.value, "kind": e.kind,
        "weight": e.weight, "color": _KIND_COLOR.get(e.kind, "#90a4ae"),
    } for e in inv.entities]
    ids = {n["id"] for n in nodes}
    links = [{"source": e.src, "target": e.dst, "rel": e.relation,
              "via": e.source}
             for e in inv.edges if e.src in ids and e.dst in ids]
    return {"nodes": nodes, "links": links}


def render(inv: Investigation, output_dir: str) -> tuple[str, str]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    slug = "".join(c if c.isalnum() else "_" for c in inv.target)[:40]
    html_path = out / f"report_{slug}_{stamp}.html"
    json_path = out / f"report_{slug}_{stamp}.json"

    json_path.write_text(json.dumps(inv.to_dict(), indent=2), encoding="utf-8")
    html_path.write_text(_html_doc(inv), encoding="utf-8")
    return str(html_path), str(json_path)


# --- HTML sections ----------------------------------------------------------

# Run rows the deep loop emits to describe ITSELF rather than an external
# source: one row per identity candidate, plus the recon-sweep summary. They
# belong in the findings table, but counting them as "sources queried" inflates
# coverage with things that never made a network call — three namesake
# candidates and a summary row turned 5 real sources into a reported 9.
def _is_synthetic_run(run) -> bool:
    return (run.source or "").startswith(("deepsearch_candidate_",
                                          "deepsearch_recon"))


def _real_source_runs(inv: Investigation) -> list:
    return [r for r in inv.runs if not _is_synthetic_run(r)]


def _stat_cards(inv: Investigation) -> str:
    results = inv.all_results
    real = _real_source_runs(inv)
    ok = sum(1 for r in real if r.status == "ok")
    onion = sum(1 for r in results if r.is_onion)
    # A source that never ran is not coverage. Counting skipped/planned sources
    # as "queried" is what turns a missing API key into an apparent clean sweep.
    queried = sum(1 for r in real
                  if r.status in ("ok", "empty", "blocked", "error"))
    not_queried = len(real) - queried
    cards = [
        ("Target type", _esc(inv.target_type)),
        ("Sources queried", str(queried)),
        ("Not queried", str(not_queried)),
        ("Live hits", str(ok)),
        ("Results", str(len(results))),
        ("Entities", str(len(inv.entities))),
        ("Onion refs", str(onion)),
        ("Guard blocks", str(inv.guardrails.get("blocked", 0))),
        ("Agent", _esc(inv.plan.get("engine", inv.plan.get("mode", "heuristic")))),
    ]
    if inv.persona:
        cards.append(("Identity", _esc(inv.persona)))
    return "".join(
        f'<div class="card"><div class="k">{k}</div><div class="v">{v}</div></div>'
        for k, v in cards)


def _runs_table(inv: Investigation) -> str:
    badge = {"ok": "b-ok", "empty": "b-mut", "planned": "b-plan",
             "skipped": "b-mut", "error": "b-err", "blocked": "b-err"}

    # Engines that made network calls come first; the deep loop's own rows
    # (recon summary, then one per identity candidate) follow under a divider.
    # Interleaved alphabetically, "Candidate 1: …" sat above "Serper" and read
    # as just another search engine that happened to answer — when it is a
    # CONCLUSION drawn from Serper's output, not a source of its own.
    def order(r):
        src = r.source or ""
        if src.startswith("deepsearch_candidate_"):
            group = 2
        elif src.startswith("deepsearch_recon"):
            group = 1
        else:
            group = 0
        return (group, r.surface, src)

    ordered = sorted(inv.runs, key=order)
    rows = []
    divider_done = False
    for run in ordered:
        if (not divider_done
                and (run.source or "").startswith("deepsearch_candidate_")):
            divider_done = True
            rows.append(
                '<tr><td colspan="4" style="padding:14px 8px 6px;'
                'border-bottom:1px solid var(--line)">'
                '<span style="font-size:11px;text-transform:uppercase;'
                'letter-spacing:.6px;color:var(--mut)">Identity candidates '
                '— derived from the sources above, not queried separately'
                '</span></td></tr>')
        res_html = ""
        for r in run.results[:12]:
            onion = ' <span class="onion">onion</span>' if r.is_onion else ""
            url = _ev_link(r.url, inv.target)
            res_html += (f'<div class="res"><div class="t">{_esc(r.title)}'
                         f'{onion}</div>{url}'
                         f'<div class="s">{_esc(r.snippet)}</div></div>')
        qhtml = ""
        if run.queries:
            qhtml = ('<div class="qset">queries: ' +
                     " ".join(f'<span class="q">{_esc(q)}</span>'
                              for q in run.queries) + '</div>')
        # The surface pill is a claim about where a query went. A candidate row
        # never made one, so it gets "derived" rather than "public" — otherwise
        # the table asserts three extra public-surface searches that never ran.
        if _is_synthetic_run(run):
            surf_cell = ('<span class="surf derived">derived</span>')
        else:
            surf_cell = (f'<span class="surf {run.surface}">'
                         f'{run.surface}</span>')
        rows.append(
            f'<tr><td>{surf_cell}</td>'
            f'<td class="lbl">{_esc(run.label)}</td>'
            f'<td><span class="badge {badge.get(run.status,"b-mut")}">'
            f'{run.status}</span></td>'
            f'<td>{_esc(run.detail)}{qhtml}<div class="reslist">{res_html}</div>'
            f'</td></tr>')
    return "".join(rows)


def _synth_html(inv: Investigation) -> str:
    s = inv.synthesis
    def ul(items):
        return "<ul>" + "".join(f"<li>{_esc(i)}</li>" for i in items) + "</ul>" if items else ""
    conf = s.get("confidence", "low")
    degraded = ""
    if s.get("ai_mode") == "heuristic":
        degraded = (
            '<div style="background:#3a1616;color:#ff8f8f;'
            'border:1px solid #5a2626;border-radius:8px;padding:10px 12px;'
            'margin-bottom:12px;font-weight:600">⚠ AI DEGRADED — this summary '
            'was written by the deterministic fallback, not the AI (the model '
            'was unavailable or its call failed this run). The search still ran, '
            'but there was no AI reasoning over the results, so read the findings '
            'as raw matches and treat a thin result as &ldquo;shallow&rdquo;, not '
            '&ldquo;nothing exists&rdquo;. Fix the provider key '
            '(GROQ / GOOGLE / NVIDIA) and re-run for real analysis.</div>')
    return f"""
      {degraded}
      <div class="conf conf-{_esc(conf)}">Confidence: {_esc(conf).upper()}</div>
      <p class="summary">{_esc(s.get('summary',''))}</p>
      <div class="synth-grid">
        <div><h4>Key findings</h4>{ul(s.get('key_findings', []))}</div>
        <div><h4>Pivots</h4>{ul(s.get('pivots', []))}</div>
        <div><h4>Next steps</h4>{ul(s.get('next_steps', []))}</div>
        <div><h4>Risk notes</h4>{ul(s.get('risk_notes', []))}</div>
      </div>"""


def _candidates_html(inv: Investigation) -> str:
    """Render the identity-resolution result: who the target actually is.

    For a common name the single most useful output is not a list of links but
    the separation of the target from their namesakes, with the evidence that
    justifies the split. That is what this section shows.
    """
    ds = inv.deep_search or {}
    cands = ds.get("candidates") or []
    if not cands:
        return ""
    ranked = sorted(cands, key=lambda c: -float(c.get("context_match") or 0))
    # A candidate the operator ruled out is a STRANGER who shares the target's
    # name. Only "skipped" was collapsed here, so /focus's "excluded" namesakes
    # kept rendering as full profile blocks — name, employer, and their personal
    # profile URLs — in a report about someone else entirely. Ruled out means
    # reduced to a line, which is the whole point of asking the operator.
    _ruled_out = {"skipped", "excluded"}
    pursued = [c for c in ranked if c.get("outcome") not in _ruled_out]
    rejected = [c for c in ranked if c.get("outcome") in _ruled_out]

    badge = {"confirmed": "b-ok", "operator-confirmed": "b-ok",
             "weak": "b-plan", "dry": "b-mut", "skipped": "b-mut",
             "excluded": "b-mut", "awaiting-selection": "b-plan",
             "budget": "b-err"}
    # "operator-confirmed" is accurate but reads as jargon in a report someone
    # else may open; say who did the confirming.
    outcome_label = {"operator-confirmed": "confirmed by operator"}
    blocks = []
    for i, c in enumerate(pursued, 1):
        score = float(c.get("context_match") or 0)
        cls = ("conf-high" if score >= 0.6 else
               "conf-medium" if score >= 0.25 else "conf-low")
        meta = " · ".join(x for x in (c.get("role"), c.get("org"),
                                      c.get("location")) if x)
        ev = c.get("evidence") or []
        ev_html = "".join(
            f'<div class="res"><div class="t">{_esc(r.get("title", ""))}</div>'
            f'{_ev_link(r.get("url", ""), inv.target)}</div>'
            for r in ev[:10])
        qs = "".join(f'<span class="q">{_esc(q)}</span>'
                     for q in (c.get("queries_run") or [])[:8])
        # A candidate that scores well on CONTEXT but has no evidence NAMING the
        # person is an inference, not a finding — its role/label (e.g. "Band
        # Member") was guessed from a school page that never mentions them. Say
        # so plainly, so the label is not read as fact.
        inferred = (
            '<div class="s" style="color:#ff8f8f;font-weight:600">'
            '⚠ inferred from context — no indexed result actually NAMES this '
            'person, so the role/label above is a guess, not a verified finding'
            '</div>'
            if not ev and score >= 0.5 else "")
        blocks.append(
            f'<div class="res" style="margin-bottom:12px">'
            f'<div class="t" style="font-size:14px">#{i} {_esc(c.get("label",""))}'
            f' <span class="conf {cls}" style="margin-left:8px">'
            f'match {score:.2f}</span>'
            f' <span class="badge {badge.get(c.get("outcome"), "b-mut")}">'
            f'{_esc(outcome_label.get(c.get("outcome"), str(c.get("outcome"))))}'
            f'</span></div>'
            + inferred
            + (f'<div class="s">{_esc(meta)}</div>' if meta else "")
            + (f'<div class="s mut">{_esc(c.get("why", ""))}</div>'
               if c.get("why") else "")
            + f'<div class="qset">rounds: {c.get("rounds", 0)} · evidence: '
              f'{len(ev)}<br>queries: {qs}</div>'
            + f'<div class="reslist">{ev_html}</div></div>')

    rej_html = ""
    if rejected:
        items = "".join(
            f'<li>{_esc(c.get("label", ""))} '
            f'<span class="mut">(match '
            f'{float(c.get("context_match") or 0):.2f}'
            + (f' — {_esc(c.get("role"))}' if c.get("role") else "")
            + ')</span></li>' for c in rejected)
        rej_html = (
            '<h4 style="margin:14px 0 4px;font-size:12.5px;color:var(--accent2)">'
            'Namesakes ruled out (not profiled)</h4>'
            f'<ul style="margin:0;padding-left:18px;font-size:12.5px">{items}</ul>')

    # Open questions come first: they are the fastest route to a better answer.
    qs = ds.get("questions") or []
    q_html = ""
    if qs:
        items = "".join(f"<li>{_esc(q)}</li>" for q in qs)
        q_html = (
            '<div class="res" style="border-color:#4a4320;background:#221f10;'
            'margin-bottom:14px">'
            '<div class="t" style="color:#ffd479">Open questions — answering '
            'any of these would narrow the result</div>'
            f'<ul style="margin:6px 0 4px;padding-left:18px;font-size:12.5px">'
            f'{items}</ul>'
            '<div class="s mut">in chat: <code>/refine &lt;your answer&gt;</code>'
            '</div></div>')

    notes = "".join(f"<li>{_esc(n)}</li>" for n in (ds.get("notes") or []))
    notes_html = (f'<div class="qset" style="margin-top:10px">Loop notes:'
                  f'<ul style="margin:4px 0;padding-left:18px">{notes}</ul></div>'
                  if notes else "")
    return (
        f'<p class="mut" style="font-size:12px">Mode: {_esc(ds.get("mode","?"))} · '
        f'{ds.get("queries_spent", 0)} quer(ies) · {ds.get("llm_calls", 0)} LLM '
        f'call(s) · {ds.get("rounds_total", 0)} deep-dive round(s)</p>'
        + q_html + "".join(blocks) + rej_html + notes_html)


def _candidates_section(inv: Investigation) -> str:
    """The whole section, or nothing when the deep loop did not run."""
    body = _candidates_html(inv)
    if not body:
        return ""
    return ('<section>\n  <h2>Identity resolution — candidates</h2>\n'
            f'  {body}\n</section>')


def _input_html(inv: Investigation) -> str:
    ctx = inv.input_context
    if not ctx or not ctx.get("files"):
        return '<p class="mut">No files supplied in input/.</p>'
    parts = []
    for img in ctx.get("images", []):
        chips = ""
        ex = img.get("extracted") or {}
        for field, vals in ex.items():
            for v in vals:
                chips += f'<span class="q">{_esc(field)}: {_esc(v)}</span>'
        ex_meta = img.get("exif") or {}
        for field in ("gps", "camera", "taken", "software"):
            if ex_meta.get(field):
                icon = "📍" if field == "gps" else "📷" if field == "camera" else "🕓"
                chips += (f'<span class="q">{icon} {_esc(field)}: '
                          f'{_esc(str(ex_meta[field]))}</span>')
        chip_html = f'<div class="qset">{chips}</div>' if chips else ""
        map_html = ""
        if ex_meta.get("map"):
            map_html = (f'<div class="s">🗺 <a href="{_esc(ex_meta["map"])}" '
                        f'target="_blank" rel="noopener">open location on map</a> '
                        f'<span class="mut">(from photo EXIF GPS)</span></div>')
        parts.append(f'<div class="res"><div class="t">🖼 {_esc(img["name"])}</div>'
                     f'<div class="s">{_esc(img["analysis"])}</div>'
                     f'{chip_html}{map_html}</div>')
    for doc in ctx.get("documents", []):
        meta = doc.get("meta") or {}
        chips = ""
        for k, v in meta.items():
            icon = "✍" if k in ("author", "last_modified_by") else "📄"
            chips += f'<span class="q">{icon} {_esc(k)}: {_esc(str(v))}</span>'
        body = ('<div class="qset">' + chips + '</div>') if chips else \
            '<div class="s mut">no readable metadata (may be scrubbed)</div>'
        parts.append(f'<div class="res"><div class="t">📄 {_esc(doc["name"])}'
                     f'</div>{body}</div>')
    for note in ctx.get("notes", [])[:8]:
        parts.append(f'<div class="res"><div class="s">{_esc(note[:600])}</div></div>')
    for sk in ctx.get("skipped", []):
        parts.append(f'<div class="res mut"><div class="s">skipped '
                     f'{_esc(sk["name"])} — {_esc(sk.get("reason",""))}</div></div>')
    return "".join(parts)


def _guard_html(inv: Investigation) -> str:
    g = inv.guardrails
    blocked = g.get("blocked_urls", [])
    body = "".join(
        f'<div class="res mut"><div class="t">⛔ {_esc(b["reason"])}</div>'
        f'<div class="u">{_esc(b["url"])}</div></div>' for b in blocked[:30])
    return (f'<p>Allowed: <b>{g.get("allowed",0)}</b> · '
            f'Blocked: <b>{g.get("blocked",0)}</b> · '
            f'Image uploads: <b>{g.get("uploads",0)}</b> · '
            f'Total decisions: <b>{g.get("total",0)}</b></p>{body}'
            or '<p class="mut">No network decisions recorded.</p>')


def _read_html(inv: Investigation) -> str:
    """Detective-read section: facts and excerpts pulled from FULL pages."""
    facts = getattr(inv, "_read_facts", None) or []
    pages = getattr(inv, "_read_pages", None) or []
    named = [p for p in pages if p.get("named")]
    if not facts and not named:
        return ""
    fact_html = ("<ul style='margin:6px 0;padding-left:18px'>"
                 + "".join(f"<li>{_esc(f)}</li>" for f in facts) + "</ul>"
                 if facts else "<p class='mut'>Pages were read but no clean fact "
                 "was extractable.</p>")
    ev = "".join(
        f'<div class="res"><div class="t">{_esc(p.get("title") or p["url"])}</div>'
        f'{_ev_link(p["url"], inv.target)}'
        f'<div class="s">{_esc((p.get("excerpt") or "")[:400])}</div></div>'
        for p in named[:10])
    return f"""
<section>
  <h2>Detective read — facts from full pages</h2>
  <p class="mut" style="font-size:12px">Read {len(named)} page(s) that name the
  target IN FULL (not search snippets), then extracted facts grounded in the
  text next to the name. This is the page-reading path, like an AI overview.</p>
  {fact_html}
  <div class="reslist">{ev}</div>
</section>"""


def _html_doc(inv: Investigation) -> str:
    graph = json.dumps(_graph_data(inv))
    legend = "".join(
        f'<span class="leg"><i style="background:{c}"></i>{k}</span>'
        for k, c in _KIND_COLOR.items())
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Black Noir — {_esc(inv.target)}</title>
<style>
:root{{--bg:#0a0b0f;--panel:#12141c;--panel2:#171a24;--line:#242838;
--fg:#e6e9f2;--mut:#7c8299;--accent:#ff3b47;--accent2:#4fc3f7}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}}
.wrap{{max-width:1200px;margin:0 auto;padding:24px}}
header{{display:flex;align-items:center;gap:16px;border-bottom:1px solid var(--line);
padding-bottom:18px;margin-bottom:22px}}
.logo{{width:46px;height:46px;border-radius:10px;background:
radial-gradient(circle at 30% 30%,#ff3b47,#7a0e14);box-shadow:0 0 24px #ff3b4755}}
h1{{margin:0;font-size:20px;letter-spacing:.5px}}
.sub{{color:var(--mut);font-size:12.5px}}
.target{{color:var(--accent2);font-weight:600}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));
gap:10px;margin-bottom:24px}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:10px;
padding:12px 14px}}
.card .k{{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.6px}}
.card .v{{font-size:20px;font-weight:700;margin-top:4px}}
section{{background:var(--panel);border:1px solid var(--line);border-radius:12px;
padding:18px 20px;margin-bottom:20px}}
h2{{margin:0 0 14px;font-size:15px;letter-spacing:.4px;
display:flex;align-items:center;gap:8px}}
h2::before{{content:"";width:8px;height:8px;border-radius:2px;background:var(--accent)}}
#graph{{width:100%;height:460px;background:
radial-gradient(circle at 50% 40%,#141826,#0a0b0f);border:1px solid var(--line);
border-radius:10px;cursor:grab}}
.legend{{margin-top:10px;display:flex;flex-wrap:wrap;gap:10px;font-size:12px;color:var(--mut)}}
.leg i{{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:5px;
vertical-align:middle}}
table{{width:100%;border-collapse:collapse}}
td,th{{text-align:left;padding:9px 8px;border-bottom:1px solid var(--line);
vertical-align:top;font-size:13px}}
.lbl{{font-weight:600;white-space:nowrap}}
.surf{{font-size:10.5px;padding:2px 7px;border-radius:20px;text-transform:uppercase;
letter-spacing:.5px}}
.surf.public{{background:#123a2a;color:#7fe0b0}}
.surf.darkweb{{background:#3a1230;color:#e98fd0}}
.surf.derived{{background:#1c2030;color:#9fb3d1;border:1px dashed var(--line)}}
.badge{{font-size:11px;padding:2px 8px;border-radius:6px;font-weight:600}}
.b-ok{{background:#123a2a;color:#7fe0b0}} .b-mut{{background:#22263a;color:var(--mut)}}
.b-plan{{background:#2a2440;color:#c0a5ff}} .b-err{{background:#3a1616;color:#ff8f8f}}
.reslist{{margin-top:8px;display:flex;flex-direction:column;gap:8px}}
.res{{background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:9px 11px}}
.res .t{{font-weight:600;font-size:12.5px}}
.res .u{{color:var(--accent2);font-size:11px;word-break:break-all;margin:2px 0;
font-family:ui-monospace,Consolas,monospace}}
.res .s{{color:var(--mut);font-size:12px;margin-top:2px}}
.onion{{background:#3a1230;color:#e98fd0;font-size:10px;padding:1px 6px;border-radius:4px}}
.qset{{margin:6px 0;font-size:11px;color:var(--mut)}}
.q{{display:inline-block;background:#1c2030;border:1px solid var(--line);
border-radius:5px;padding:1px 7px;margin:2px 3px 0 0;color:#9fb3d1;
font-family:ui-monospace,Consolas,monospace}}
.mut{{color:var(--mut)}}
.conf{{display:inline-block;padding:4px 12px;border-radius:8px;font-weight:700;
font-size:12px;margin-bottom:10px}}
.conf-high{{background:#123a2a;color:#7fe0b0}}
.conf-medium{{background:#3a3312;color:#ffd479}}
.conf-low{{background:#22263a;color:var(--mut)}}
.summary{{font-size:14px}}
.synth-grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
.synth-grid h4{{margin:0 0 6px;font-size:12.5px;color:var(--accent2)}}
.synth-grid ul{{margin:0;padding-left:18px}} .synth-grid li{{margin:3px 0;font-size:12.5px}}
footer{{color:var(--mut);font-size:11.5px;text-align:center;padding:20px 0}}
.pill{{display:inline-block;background:#22263a;color:var(--mut);padding:2px 9px;
border-radius:20px;font-size:11px;margin-right:6px}}
@media(max-width:720px){{.synth-grid{{grid-template-columns:1fr}}}}
</style></head><body><div class="wrap">
<header>
  <div class="logo"></div>
  <div>
    <h1>BLACK NOIR <span class="sub">· deep-search OSINT agent v1.0</span></h1>
    <div class="sub">Target <span class="target">{_esc(inv.target)}</span>
      · started {_esc(inv.started)}
      · surfaces {" ".join(f'<span class="pill">{_esc(s)}</span>' for s in inv.surfaces)}</div>
  </div>
</header>

<div class="cards">{_stat_cards(inv)}</div>

<section>
  <h2>Entity link graph</h2>
  <canvas id="graph"></canvas>
  <div class="legend">{legend}</div>
</section>

{_candidates_section(inv)}
{_read_html(inv)}
<section>
  <h2>Agent synthesis</h2>
  {_synth_html(inv)}
  <div class="mut" style="margin-top:10px;font-size:11.5px">
    Planner reasoning: {_esc(inv.plan.get('reasoning',''))}</div>
</section>

<section>
  <h2>Sources &amp; findings</h2>
  <table><thead><tr><th>Surface</th><th>Source</th><th>Status</th>
  <th>Detail / results</th></tr></thead><tbody>{_runs_table(inv)}</tbody></table>
</section>

<section>
  <h2>Input-folder analysis (visual + logical)</h2>
  {_input_html(inv)}
</section>

<section>
  <h2>Guardrail audit log</h2>
  {_guard_html(inv)}
</section>

<footer>
  Black Noir CLI — index metadata only · no onion service contacted · nothing
  downloaded or clicked. For authorized OSINT / research use.
</footer>
</div>
<script>
const DATA = {graph};
const cv = document.getElementById('graph');
const ctx = cv.getContext('2d');
let W, H;
function size(){{ W = cv.width = cv.clientWidth*devicePixelRatio;
  H = cv.height = cv.clientHeight*devicePixelRatio; }}
size(); window.addEventListener('resize', size);
const nodes = DATA.nodes.map((n,i)=>({{...n,
  x: W/2 + Math.cos(i)*180*devicePixelRatio,
  y: H/2 + Math.sin(i*1.7)*140*devicePixelRatio, vx:0, vy:0}}));
const idx = Object.fromEntries(nodes.map((n,i)=>[n.id,i]));
const links = DATA.links.map(l=>({{s:idx[l.source], t:idx[l.target]}})).filter(l=>l.s!=null&&l.t!=null);
let drag=null, off={{x:0,y:0}}, pan={{x:0,y:0}}, zoom=1;
function tick(){{
  for(const n of nodes){{ n.vx*=0.85; n.vy*=0.85; }}
  for(let i=0;i<nodes.length;i++) for(let j=i+1;j<nodes.length;j++){{
    const a=nodes[i],b=nodes[j]; let dx=a.x-b.x,dy=a.y-b.y;
    let d=Math.hypot(dx,dy)||1; const f=(9000*devicePixelRatio)/(d*d);
    dx/=d;dy/=d; a.vx+=dx*f;a.vy+=dy*f;b.vx-=dx*f;b.vy-=dy*f;
  }}
  for(const l of links){{ const a=nodes[l.s],b=nodes[l.t];
    let dx=b.x-a.x,dy=b.y-a.y; let d=Math.hypot(dx,dy)||1;
    const f=(d-150*devicePixelRatio)*0.02; dx/=d;dy/=d;
    a.vx+=dx*f;a.vy+=dy*f;b.vx-=dx*f;b.vy-=dy*f; }}
  for(const n of nodes){{ if(n===drag) continue;
    n.vx+=(W/2-n.x)*0.002; n.vy+=(H/2-n.y)*0.002; n.x+=n.vx; n.y+=n.vy; }}
}}
function draw(){{
  ctx.setTransform(zoom,0,0,zoom,pan.x,pan.y);
  ctx.clearRect(-pan.x/zoom,-pan.y/zoom,W/zoom,H/zoom);
  ctx.lineWidth=1*devicePixelRatio; ctx.strokeStyle='#2a2f45';
  for(const l of links){{ const a=nodes[l.s],b=nodes[l.t];
    ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke(); }}
  for(const n of nodes){{ const r=(6+Math.min(n.weight,8)*1.6)*devicePixelRatio;
    ctx.beginPath();ctx.arc(n.x,n.y,r,0,7); ctx.fillStyle=n.color;
    ctx.shadowColor=n.color;ctx.shadowBlur=12;ctx.fill();ctx.shadowBlur=0;
    ctx.fillStyle='#e6e9f2';ctx.font=(11*devicePixelRatio)+'px Segoe UI';
    ctx.fillText(n.label.slice(0,26), n.x+r+3, n.y+4); }}
}}
function loop(){{ tick(); draw(); requestAnimationFrame(loop); }} loop();
function pos(e){{ const r=cv.getBoundingClientRect();
  return {{x:((e.clientX-r.left)*devicePixelRatio-pan.x)/zoom,
           y:((e.clientY-r.top)*devicePixelRatio-pan.y)/zoom}}; }}
cv.addEventListener('mousedown',e=>{{ const p=pos(e);
  for(const n of nodes){{ if(Math.hypot(n.x-p.x,n.y-p.y)<16*devicePixelRatio){{
    drag=n; off={{x:n.x-p.x,y:n.y-p.y}}; cv.style.cursor='grabbing'; return; }} }}
  drag='pan'; off={{x:e.clientX-pan.x,y:e.clientY-pan.y}}; }});
window.addEventListener('mousemove',e=>{{ if(!drag) return;
  if(drag==='pan'){{ pan.x=e.clientX-off.x; pan.y=e.clientY-off.y; return; }}
  const p=pos(e); drag.x=p.x+off.x; drag.y=p.y+off.y; drag.vx=drag.vy=0; }});
window.addEventListener('mouseup',()=>{{ drag=null; cv.style.cursor='grab'; }});
cv.addEventListener('wheel',e=>{{ e.preventDefault();
  zoom*=e.deltaY<0?1.1:0.9; zoom=Math.max(0.3,Math.min(3,zoom)); }},{{passive:false}});
</script>
</body></html>"""
