"""Parsing: read a review's stored output into normalized reports.

A whole-repo review writes confirmed findings as `findings/*.md` and as a `findings.json`,
and a diff run yields findings in memory. This module turns the stored markdown and json
forms into the shared Report, so one scorer reads a coded run and an agent run alike. The
cited files come from any source path in the body, matched against the data-driven source
extensions so the scorer names no language, the same boundary the product keeps.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from codejury.detection import load_detection
from evals.schema import Report


@lru_cache(maxsize=1)
def _file_re() -> re.Pattern:
    # longest extension first so app.tsx matches tsx not its ts tail
    exts = sorted((e.lstrip(".") for e in load_detection().source_extensions), key=len, reverse=True)
    alt = "|".join(re.escape(e) for e in exts)
    return re.compile(rf"[\w./-]+\.(?:{alt})")


def parse_finding_md(text: str, name: str) -> Report:
    """Read one findings/<name>.md into a Report. Endpoint comes from the Source line,
    category from Type, the cited files from any source path in the body."""
    def field(key: str) -> str:
        m = re.search(rf"(?im)^\s*-?\s*{key}\s*:\s*(.+?)\s*$", text)
        return m.group(1).strip().strip("`") if m else ""
    files = sorted(set(_file_re().findall(text)))
    return Report.make(name, field("source"), field("type"), files)


def reports_from_findings_dir(d: str | Path) -> list[Report]:
    d = Path(d)
    if not d.is_dir():
        raise ValueError(f"no findings directory at {d}, finalize a review first")
    return [parse_finding_md(p.read_text(encoding="utf-8"), p.stem) for p in sorted(d.glob("*.md"))]


def reports_from_json(path: str | Path) -> list[Report]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = data["findings"] if isinstance(data, dict) else data
    return [
        Report.make(
            str(r.get("id") or f"r{i}"),
            str(r.get("entry") or r.get("source") or ""),
            str(r.get("category") or r.get("type") or ""),
            [str(r["file"])] if r.get("file") else [],
        )
        for i, r in enumerate(rows)
    ]
