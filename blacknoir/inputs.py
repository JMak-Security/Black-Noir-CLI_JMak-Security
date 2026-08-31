"""Process the `input/` folder.

The user drops extra context about a target here. Black Noir reads it two ways:
  * VISUALLY  -> images are described/OCR'd with Claude vision (if a key exists),
                 otherwise recorded as evidence with metadata only.
  * LOGICALLY -> text / csv / json / md are read and mined for identifiers.

It never executes, unzips or opens anything active — only reads bytes it is
willing to display. Oversized and binary blobs are catalogued, not parsed.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp"}
TEXT_EXT = {".txt", ".md", ".csv", ".json", ".log", ".tsv", ".yaml", ".yml"}
DOC_EXT = {".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods"}
MAX_TEXT_BYTES = 200_000
MAX_IMAGE_BYTES = 4_500_000
MAX_DOC_BYTES = 30_000_000

_MEDIA = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
          ".gif": "image/gif", ".webp": "image/webp"}


def _gps_to_deg(val, ref) -> float | None:
    """Convert an EXIF (deg, min, sec) rational tuple + hemisphere ref to float."""
    try:
        d, m, s = (float(x) for x in val)
        deg = d + m / 60.0 + s / 3600.0
        if str(ref).upper() in ("S", "W"):
            deg = -deg
        return deg
    except Exception:
        return None


def extract_exif(path: str) -> dict:
    """Locally read EXIF/GPS/camera metadata from an image. No network, no
    write — just parses bytes already on disk. Returns {} if PIL is absent or
    the image carries no EXIF (common for screenshots / scrubbed uploads)."""
    try:
        from PIL import Image, ExifTags  # optional dependency
    except Exception:
        return {}
    try:
        img = Image.open(path)
        raw = img._getexif() or {}
    except Exception:
        return {}
    if not raw:
        return {}
    tags = {ExifTags.TAGS.get(k, k): v for k, v in raw.items()}
    out: dict = {}
    make = str(tags.get("Make", "")).strip()
    model = str(tags.get("Model", "")).strip()
    if make or model:
        out["camera"] = f"{make} {model}".strip()
    if tags.get("DateTimeOriginal"):
        out["taken"] = str(tags["DateTimeOriginal"])
    if tags.get("Software"):
        out["software"] = str(tags["Software"])
    gps_raw = tags.get("GPSInfo")
    if isinstance(gps_raw, dict):
        gps = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps_raw.items()}
        lat = _gps_to_deg(gps.get("GPSLatitude"), gps.get("GPSLatitudeRef"))
        lon = _gps_to_deg(gps.get("GPSLongitude"), gps.get("GPSLongitudeRef"))
        if lat is not None and lon is not None:
            out["gps"] = f"{lat:.6f}, {lon:.6f}"
            out["map"] = f"https://www.google.com/maps?q={lat:.6f},{lon:.6f}"
    return out


def _pdf_meta(path: str) -> dict:
    """Author/creator/dates from a PDF Info dictionary — stdlib regex, no fetch."""
    import re as _re
    out: dict = {}
    try:
        with open(path, "rb") as fh:
            raw = fh.read(2_000_000)  # metadata lives near the trailer/head
    except Exception:
        return {}
    for field in ("Author", "Creator", "Producer", "Title",
                  "CreationDate", "ModDate"):
        m = _re.search(rf"/{field}\s*\(((?:[^()\\]|\\.)*)\)", raw.decode(
            "latin-1", "ignore"))
        if m and m.group(1).strip():
            val = m.group(1).encode("latin-1", "ignore").decode(
                "utf-8", "ignore").strip()
            out[field.lower()] = val[:120]
    return out


def _office_meta(path: str) -> dict:
    """dc:creator / lastModifiedBy / dates / app from an OOXML/ODF container."""
    import zipfile
    import xml.etree.ElementTree as ET
    out: dict = {}
    try:
        zf = zipfile.ZipFile(path)
        names = set(zf.namelist())
    except Exception:
        return {}
    # OOXML (docx/xlsx/pptx)
    if "docProps/core.xml" in names:
        try:
            root = ET.fromstring(zf.read("docProps/core.xml"))
            for tag, key in (("creator", "author"),
                             ("lastModifiedBy", "last_modified_by"),
                             ("title", "title"), ("created", "created"),
                             ("modified", "modified"), ("revision", "revision")):
                el = root.find(f".//{{*}}{tag}")
                if el is not None and (el.text or "").strip():
                    out[key] = el.text.strip()[:120]
        except Exception:
            pass
        if "docProps/app.xml" in names:
            try:
                root = ET.fromstring(zf.read("docProps/app.xml"))
                for tag, key in (("Application", "application"),
                                 ("Company", "company")):
                    el = root.find(f".//{{*}}{tag}")
                    if el is not None and (el.text or "").strip():
                        out[key] = el.text.strip()[:120]
            except Exception:
                pass
    # ODF (odt/ods)
    elif "meta.xml" in names:
        try:
            root = ET.fromstring(zf.read("meta.xml"))
            for tag, key in (("creator", "author"), ("title", "title"),
                             ("creation-date", "created"), ("date", "modified"),
                             ("generator", "application")):
                el = root.find(f".//{{*}}{tag}")
                if el is not None and (el.text or "").strip():
                    out[key] = el.text.strip()[:120]
        except Exception:
            pass
    return out


def extract_doc_meta(path: str, ext: str) -> dict:
    """Local author/revision metadata from a PDF or Office/ODF document.

    Pure-stdlib, read-only: opens the container to read its metadata XML (or the
    PDF Info dict) and nothing else. Never executes macros, follows links, or
    extracts embedded files. Returns {} when there's no usable metadata."""
    if ext == ".pdf":
        return _pdf_meta(path)
    return _office_meta(path)


def process_input_dir(input_dir: str, vision=None) -> dict:
    """Return an input-context dict fed to the agent + report.

    `vision` is an optional callable(image_b64, media_type, filename) -> str
    that returns a textual analysis of an image (wired to Claude vision).
    """
    ctx: dict = {"files": [], "notes": [], "images": [], "documents": [],
                 "skipped": []}
    root = Path(input_dir)
    if not root.exists():
        return ctx

    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        ext = path.suffix.lower()
        size = path.stat().st_size
        entry = {"name": path.name, "path": str(path), "ext": ext, "size": size}
        ctx["files"].append(entry)

        if ext in TEXT_EXT and size <= MAX_TEXT_BYTES:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                ctx["notes"].append(f"[{path.name}] {text[:MAX_TEXT_BYTES]}")
            except Exception as exc:
                ctx["skipped"].append({**entry, "reason": str(exc)})
        elif ext in IMAGE_EXT and size <= MAX_IMAGE_BYTES:
            analysis, extracted, subject_type = "", {}, "other"
            leads, identifiability = [], ""
            try:
                raw = path.read_bytes()
                b64 = base64.standard_b64encode(raw).decode("ascii")
                if vision is not None:
                    res = vision(b64, _MEDIA.get(ext, "image/png"), path.name)
                    if isinstance(res, dict):
                        analysis = res.get("analysis", "")
                        extracted = res.get("extracted", {}) or {}
                        subject_type = res.get("subject_type", "other") or "other"
                        leads = res.get("leads", []) or []
                        identifiability = res.get("identifiability", "") or ""
                    else:  # tolerate a plain-string vision callback
                        analysis = str(res)
            except Exception as exc:
                analysis = f"(vision unavailable: {exc})"
            exif = extract_exif(str(path))
            ctx["images"].append({
                "name": path.name, "path": str(path),
                "media_type": _MEDIA.get(ext, "image/png"),
                "analysis": analysis or "(image catalogued; enable vision for analysis)",
                "extracted": extracted, "subject_type": subject_type,
                "leads": leads, "identifiability": identifiability,
                "exif": exif,
            })
        elif ext in DOC_EXT and size <= MAX_DOC_BYTES:
            meta = extract_doc_meta(str(path), ext)
            ctx["documents"].append({
                "name": path.name, "path": str(path), "ext": ext,
                "meta": meta,
            })
            if not meta:
                ctx["skipped"].append({
                    **entry,
                    "reason": "document catalogued — no readable metadata",
                })
        else:
            ctx["skipped"].append({
                **entry,
                "reason": "binary/oversized — catalogued, not parsed (safety)",
            })
    return ctx


def summarize_input(ctx: dict) -> str:
    parts = []
    if ctx["files"]:
        parts.append(f"{len(ctx['files'])} file(s) in input/")
    if ctx["notes"]:
        joined = " ".join(ctx["notes"])
        parts.append("TEXT CONTEXT: " + joined[:4000])
    if ctx["images"]:
        for img in ctx["images"]:
            parts.append(f"IMAGE {img['name']}: {img['analysis'][:600]}")
            ex = img.get("exif") or {}
            if ex:
                bits = []
                if ex.get("gps"):
                    bits.append(f"GPS {ex['gps']} ({ex.get('map','')})")
                if ex.get("camera"):
                    bits.append(f"camera {ex['camera']}")
                if ex.get("taken"):
                    bits.append(f"taken {ex['taken']}")
                if ex.get("software"):
                    bits.append(f"software {ex['software']}")
                if bits:
                    parts.append(f"  EXIF: {' · '.join(bits)}")
    for doc in ctx.get("documents", []):
        meta = doc.get("meta") or {}
        if meta:
            bits = [f"{k}={v}" for k, v in meta.items()]
            parts.append(f"DOCUMENT {doc['name']} metadata: {' · '.join(bits)}")
    if ctx["skipped"]:
        parts.append(f"{len(ctx['skipped'])} file(s) skipped for safety.")
    return "\n".join(parts) if parts else "input/ is empty."
