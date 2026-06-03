"""Shared markdown-doc plumbing: frontmatter parsing and directory loading.

Both the vulnerability rules (`data/rules`) and the language/framework guides
(`data/languages`, `data/frameworks`) are markdown files with a YAML frontmatter
and a body. This holds only that shared mechanics. Each caller builds its own
typed record and applies its own selection, since rules select by trigger text
and guides select by detection signals.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

import yaml


def parse_frontmatter(text: str) -> tuple[dict, str]:
    """Return (frontmatter dict, body). A doc with no `---` frontmatter is ({}, text)."""
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) == 3:
            meta = yaml.safe_load(parts[1]) or {}
            return (meta if isinstance(meta, dict) else {}), parts[2].strip()
    return {}, text


def iter_md_docs(directory: str | Path) -> Iterator[tuple[Path, dict, str]]:
    """Yield (path, meta, body) for each `*.md` in `directory`, skipping `SKILL.md`.
    Yields nothing if the directory does not exist. Sorted by path for determinism."""
    root = Path(directory)
    if not root.is_dir():
        return
    for path in sorted(root.glob("*.md")):
        if path.name == "SKILL.md":
            continue
        meta, body = parse_frontmatter(path.read_text(encoding="utf-8"))
        yield path, meta, body
