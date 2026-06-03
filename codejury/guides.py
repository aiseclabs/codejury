"""Language and framework review guides as data.

Each `data/languages/*.md` and `data/frameworks/*.md` is a knowledge unit: YAML
frontmatter declaring how to detect the language or framework in a target repo
(file-name globs, dependency-manifest substrings, import markers), and a body of
review guidance (where input enters, common sinks, auth conventions, gotchas).

Selection is generic: a guide applies when its detect signals fire on the repo.
Adding a language or framework is a drop-in file under the right directory, no
code change, which keeps the unbounded language/framework axis out of code.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from codejury.resources import FRAMEWORKS_DIR, LANGUAGES_DIR

_DIFF_PATH = re.compile(r"^(?:\+\+\+ b/|diff --git a/\S+ b/)(\S+)", re.MULTILINE)


@dataclass(frozen=True, kw_only=True)
class Guide:
    id: str
    kind: str            # "language" or "framework"
    title: str
    detect_files: tuple[str, ...]
    detect_manifest: tuple[str, ...]
    detect_imports: tuple[str, ...]
    body: str


def _parse(path: Path, kind: str) -> Guide:
    text = path.read_text(encoding="utf-8")
    meta: dict = {}
    body = text
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) == 3:
            meta = yaml.safe_load(parts[1]) or {}
            body = parts[2].strip()
    detect = meta.get("detect", {}) or {}
    return Guide(
        id=str(meta.get("id", path.stem)),
        kind=kind,
        title=str(meta.get("title", path.stem)),
        detect_files=tuple(str(f) for f in detect.get("files", [])),
        detect_manifest=tuple(str(m).lower() for m in detect.get("manifest", [])),
        detect_imports=tuple(str(i) for i in detect.get("imports", [])),
        body=body,
    )


def load_guides(languages_dir=LANGUAGES_DIR, frameworks_dir=FRAMEWORKS_DIR) -> list[Guide]:
    out: list[Guide] = []
    for directory, kind in ((languages_dir, "language"), (frameworks_dir, "framework")):
        root = Path(directory)
        if root.is_dir():
            out += [_parse(p, kind) for p in sorted(root.glob("*.md")) if p.name != "SKILL.md"]
    return out


def _matches(guide: Guide, files: list[str], text: str) -> bool:
    if any(fnmatch.fnmatch(f, pat) for pat in guide.detect_files for f in files):
        return True
    if any(m in text for m in guide.detect_manifest):
        return True
    if any(i in text for i in guide.detect_imports):
        return True
    return False


def select_guides(files, *, text: str = "", guides: list[Guide] | None = None) -> list[Guide]:
    """The guides whose detect signals fire on the target, languages first then
    frameworks. `files` are the target's file paths; `text` is content to scan for
    manifest substrings and import markers (a repo's manifests, or a diff body)."""
    pool = load_guides() if guides is None else guides
    file_list = list(files)
    blob = text.lower()
    return [g for g in pool if _matches(g, file_list, blob)]


def _changed_paths(diff: str) -> list[str]:
    """The file paths touched by a unified diff (from its `+++ b/` / `diff --git` headers)."""
    return _DIFF_PATH.findall(diff)


def guides_for_diff(diff: str, *, guides: list[Guide] | None = None) -> str:
    """Concatenated bodies of the language/framework guides relevant to a diff, by
    its changed paths and its content. Empty when nothing matches."""
    selected = select_guides(_changed_paths(diff), text=diff, guides=guides)
    return "\n\n---\n\n".join(g.body for g in selected)
