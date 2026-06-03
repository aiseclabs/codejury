"""Language and framework review guides as data.

Each `data/languages/*.md` and `data/frameworks/*.md` is a knowledge unit: YAML
frontmatter declaring how to detect the language or framework in a target repo
by file-name globs, dependency-manifest substrings, import markers, or
language-neutral content tokens such as a protocol's wire fields, and a body of
review guidance covering where input enters, common sinks, auth conventions, and
gotchas.

Selection is generic: a guide applies when its detect signals fire on the repo.
Adding a language or framework is a drop-in file under the right directory, no
code change, which keeps the unbounded language/framework axis out of code.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass

from codejury.mddoc import iter_md_docs
from codejury.resources import FRAMEWORKS_DIR, LANGUAGES_DIR, TOPICS_DIR


@dataclass(frozen=True, kw_only=True)
class Guide:
    id: str
    kind: str            # "language" or "framework"
    title: str
    detect_files: tuple[str, ...]
    detect_manifest: tuple[str, ...]
    detect_imports: tuple[str, ...]
    detect_content: tuple[str, ...]       # language-neutral content tokens, for example a protocol's wire fields
    entrypoint_files: tuple[str, ...]     # globs for files likely to define entrypoints
    entrypoint_markers: tuple[str, ...]   # content markers for files that define entrypoints
    body: str


def _guide(path, meta: dict, body: str) -> Guide:
    detect = meta.get("detect", {}) or {}
    return Guide(
        id=str(meta.get("id", path.stem)),
        kind=str(meta.get("kind", "")).strip().lower(),
        title=str(meta.get("title", path.stem)),
        detect_files=tuple(str(f) for f in detect.get("files", [])),
        detect_manifest=tuple(str(m).lower() for m in detect.get("manifest", [])),
        detect_imports=tuple(str(i) for i in detect.get("imports", [])),
        detect_content=tuple(str(c).lower() for c in detect.get("content", [])),
        entrypoint_files=tuple(str(g) for g in meta.get("entrypoint_files", [])),
        entrypoint_markers=tuple(str(m) for m in meta.get("entrypoint_markers", [])),
        body=body,
    )


def entrypoint_globs(guides: list[Guide]) -> tuple[str, ...]:
    """The entrypoint-file globs declared by a set of guides, deduplicated."""
    seen: dict[str, None] = {}
    for g in guides:
        for pat in g.entrypoint_files:
            seen.setdefault(pat, None)
    return tuple(seen)


def entrypoint_markers(guides: list[Guide]) -> tuple[str, ...]:
    """The entrypoint content markers declared by a set of guides, deduplicated."""
    seen: dict[str, None] = {}
    for g in guides:
        for m in g.entrypoint_markers:
            seen.setdefault(m, None)
    return tuple(seen)


def load_guides(languages_dir=LANGUAGES_DIR, frameworks_dir=FRAMEWORKS_DIR, topics_dir=TOPICS_DIR) -> list[Guide]:
    # kind comes from each guide's frontmatter, the single source of truth. The
    # directories are a convenience for humans and never decide kind, so the two
    # cannot drift.
    out: list[Guide] = []
    for directory in (languages_dir, frameworks_dir, topics_dir):
        out += [_guide(path, meta, body) for path, meta, body in iter_md_docs(directory)]
    return out


def _matches(guide: Guide, files: list[str], text: str) -> bool:
    if any(fnmatch.fnmatch(f, pat) for pat in guide.detect_files for f in files):
        return True
    if any(m in text for m in guide.detect_manifest):
        return True
    if any(i in text for i in guide.detect_imports):
        return True
    if any(c in text for c in guide.detect_content):
        return True
    return False


def select_guides(files, *, text: str = "", guides: list[Guide] | None = None) -> list[Guide]:
    """The guides whose detect signals fire on the target, languages first then
    frameworks. `files` are the target's file paths. `text` is content to scan for
    manifest substrings, import markers, and language-neutral content tokens such
    as a protocol's wire fields, namely a repo's manifests plus a source sample,
    or a diff body."""
    pool = load_guides() if guides is None else guides
    file_list = list(files)
    blob = text.lower()
    return [g for g in pool if _matches(g, file_list, blob)]
