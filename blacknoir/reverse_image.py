"""Reverse-image search — as close to a real lookup as is possible on clearnet.

Three tiers, strongest first:

  1. SauceNAO  — real API. Uploads the image file (multipart) and returns
                 structured matches WITH source site + creator name + similarity.
                 Best-in-class for artwork attribution. Optional SAUCENAO_API_KEY
                 raises the rate limit; it also works keyless at a low rate.
  2. IQDB      — real multipart upload; parses the HTML match table (booru/art).
  3. Prepared  — Google Lens / Yandex / TinEye / Bing Visual accept a file only
                 through their UI, so we hand back ready-to-open upload links.
                 Nothing is uploaded to these; the operator drops the file.

Safety: uploads go only to the allow-listed reverse hosts, only in --live mode,
and each upload is written to the guardrail audit log. No image ever leaves the
machine in plan-only mode. No result link is followed; no file is downloaded.
"""

from __future__ import annotations

import os
import re
from urllib.parse import urlencode

from .models import SearchResult, SourceRun

try:
    from bs4 import BeautifulSoup  # type: ignore
    _HAS_BS4 = True
except Exception:
    BeautifulSoup = None  # type: ignore
    _HAS_BS4 = False

MAX_MATCHES = 10
MIN_SIMILARITY = 30.0  # drop very weak SauceNAO hits

# General reverse-image engines (file only via UI) -> prepared links.
# For people, Yandex and Google Lens are the strongest, so they lead.
_PREPARED_GENERAL = [
    ("yandex_images", "Yandex Images",
     "https://yandex.com/images/search?rpt=imageview",
     "best general/face reverse-image engine (upload the file)"),
    ("google_lens", "Google Lens", "https://lens.google.com/",
     "strong for people, places, products (upload the file)"),
    ("bing_visual", "Bing Visual Search", "https://www.bing.com/visualsearch",
     "general reverse-image (upload the file)"),
    ("tineye", "TinEye", "https://tineye.com/",
     "finds exact copies / earliest appearance (upload the file)"),
]

# Dedicated face-recognition engines — MANUAL links only, never auto-uploaded.
# Provided for authorized/consented investigations of the subject.
_PREPARED_FACE = [
    ("pimeyes", "PimEyes (facial recognition)", "https://pimeyes.com/en",
     "facial recognition — use ONLY with authorization/consent (legally "
     "restricted in some regions)"),
    ("facecheck", "FaceCheck.ID (facial recognition)", "https://facecheck.id/",
     "facial recognition — use ONLY with authorization/consent"),
]


def _read(path: str) -> bytes | None:
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except Exception:
        return None


# --- SauceNAO ---------------------------------------------------------------

def _saucenao(path: str, name: str, fetcher, api_key: str, live: bool) -> SourceRun:
    if not live:
        return SourceRun("saucenao", "SauceNAO", "public", "planned",
                         detail=("plan-only: would upload the image to the "
                                 "SauceNAO API for attribution."),
                         queries=[name])
    raw = _read(path)
    if raw is None:
        return SourceRun("saucenao", "SauceNAO", "public", "error",
                         detail="could not read image bytes")
    params = {"output_type": "2", "numres": str(MAX_MATCHES), "db": "999"}
    if api_key:
        params["api_key"] = api_key
    url = "https://saucenao.com/search.php?" + urlencode(params)
    data = fetcher.post(url, files={"file": (name, raw,
                        "application/octet-stream")}, as_json=True)
    if data is None:
        return SourceRun("saucenao", "SauceNAO", "public", "blocked",
                         detail=("no response (rate-limited or key needed). "
                                 "Set SAUCENAO_API_KEY to improve reliability."),
                         queries=[name])
    hdr = data.get("header", {}) if isinstance(data, dict) else {}
    if hdr.get("status", 0) < 0:
        return SourceRun("saucenao", "SauceNAO", "public", "error",
                         detail=f"api: {hdr.get('message','error')}", queries=[name])
    results = []
    for r in (data.get("results") or []):
        h, d = r.get("header", {}), r.get("data", {})
        try:
            sim = float(h.get("similarity", 0))
        except Exception:
            sim = 0.0
        if sim < MIN_SIMILARITY:
            continue
        urls = d.get("ext_urls", []) or []
        creator = (d.get("member_name") or d.get("creator")
                   or d.get("author_name") or d.get("artist") or "")
        title = (d.get("title") or d.get("source")
                 or h.get("index_name", "match"))
        results.append(SearchResult(
            "saucenao", "public",
            title=f"{sim:.1f}% · {title}"[:200],
            url=urls[0] if urls else "",
            snippet=(f"site: {h.get('index_name','?')} · "
                     f"creator: {creator or 'n/a'} · "
                     f"other links: {', '.join(urls[1:3])}")[:300],
            meta={"similarity": sim, "creator": creator,
                  "site": h.get("index_name", ""), "all_urls": urls}))
    results.sort(key=lambda x: -x.meta.get("similarity", 0))
    return SourceRun("saucenao", "SauceNAO", "public",
                     "ok" if results else "empty",
                     detail=f"queried SauceNAO for {name}", results=results,
                     queries=[name])


# --- IQDB -------------------------------------------------------------------

def _iqdb(path: str, name: str, fetcher, live: bool) -> SourceRun:
    if not live:
        return SourceRun("iqdb", "IQDB", "public", "planned",
                         detail="plan-only: would upload the image to IQDB.",
                         queries=[name])
    raw = _read(path)
    if raw is None:
        return SourceRun("iqdb", "IQDB", "public", "error",
                         detail="could not read image bytes")
    html = fetcher.post("https://iqdb.org/",
                        files={"file": (name, raw, "application/octet-stream")})
    if not html:
        return SourceRun("iqdb", "IQDB", "public", "blocked",
                         detail="no response from IQDB", queries=[name])
    results = _parse_iqdb(html)
    return SourceRun("iqdb", "IQDB", "public", "ok" if results else "empty",
                     detail=f"queried IQDB for {name}", results=results,
                     queries=[name])


def _parse_iqdb(html: str) -> list[SearchResult]:
    out: list[SearchResult] = []
    if _HAS_BS4:
        soup = BeautifulSoup(html, "html.parser")
        tables = soup.find_all("table")
    else:
        tables = []
    for tbl in tables:
        text = tbl.get_text(" ", strip=True)
        if "similarity" not in text.lower():
            continue
        a = tbl.find("a", href=True)
        if not a:
            continue
        href = a["href"]
        if href.startswith("//"):
            href = "https:" + href
        if not href.startswith("http"):
            continue
        m = re.search(r"(\d+)%\s*similarity", text, re.I)
        sim = m.group(1) if m else "?"
        label = "best match" if "best match" in text.lower() else "match"
        out.append(SearchResult(
            "iqdb", "public", title=f"{sim}% · IQDB {label}",
            url=href, snippet=text[:200],
            meta={"similarity": float(sim) if sim.isdigit() else 0}))
        if len(out) >= MAX_MATCHES:
            break
    return out


# --- prepared links ---------------------------------------------------------

def _prepared_run(engines, label, detail) -> SourceRun:
    results = [SearchResult(
        key, "public", title=f"Open {name} → upload the image",
        url=base, snippet=note + " — no image is sent here by Black Noir")
        for key, name, base, note in engines]
    return SourceRun("reverse_prepared", label, "public",
                     "ok" if results else "empty", detail=detail, results=results)


# --- orchestrator -----------------------------------------------------------

def reverse_search(images: list[dict], fetcher, api_key: str,
                   live: bool, max_images: int = 3) -> list[SourceRun]:
    """Route reverse-image search by what each image actually is.

      artwork/logo -> SauceNAO + IQDB (art/booru matchers) + general links
      person/scene -> general links (Yandex/Lens lead) + face links (manual);
                      art matchers are skipped (they whiff on faces, and we
                      avoid needlessly uploading a person's face to an art DB)
      other/doc    -> general links + SauceNAO (labelled)
    """
    subj = "other"
    for img in images:
        st = (img.get("subject_type") or "other").lower()
        if st in ("person", "scene"):
            subj = "person"
            break
        if st in ("artwork", "logo"):
            subj = "artwork"

    runs: list[SourceRun] = [
        _prepared_run(_PREPARED_GENERAL, "Reverse-image (manual upload)",
                      "prepared upload links — nothing uploaded here")]

    if subj == "person":
        runs.append(_prepared_run(
            _PREPARED_FACE, "Face search (manual, authorized use)",
            "facial-recognition engines — manual, authorization/consent required"))
        runs.append(SourceRun(
            "saucenao", "SauceNAO", "public", "skipped",
            detail="skipped: SauceNAO is an art/anime DB, not for faces."))
        runs.append(SourceRun(
            "iqdb", "IQDB", "public", "skipped",
            detail="skipped: IQDB is an art/booru DB, not for faces."))
        return runs

    # artwork / logo / other -> run the real art matchers
    for img in images[:max_images]:
        path, name = img.get("path"), img.get("name", "image")
        if not path or not os.path.exists(path):
            continue
        runs.append(_saucenao(path, name, fetcher, api_key, live))
        runs.append(_iqdb(path, name, fetcher, live))
    return runs
