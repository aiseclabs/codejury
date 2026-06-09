"""Language and framework review guides as data.

Each `knowledge/guides/languages/*.md` and `knowledge/guides/frameworks/*.md` is a knowledge unit: YAML
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

from codejury.markdown_docs import iter_md_docs
from codejury.resources import FRAMEWORKS_DIR, LANGUAGES_DIR, PROTOCOLS_DIR


@dataclass(frozen=True, kw_only=True)
class Guide:
    id: str
    kind: str            # "language", "framework", or "protocol"
    language: str        # for a framework, the id of the language it belongs to, otherwise empty
    title: str
    detect_files: tuple[str, ...]
    detect_manifest: tuple[str, ...]
    detect_imports: tuple[str, ...]
    detect_content: tuple[str, ...]       # language-neutral content tokens, for example a protocol's wire fields
    entrypoint_files: tuple[str, ...]     # globs for files likely to define entrypoints
    entrypoint_markers: tuple[str, ...]   # content markers for files that define entrypoints
    logic_layers: tuple[str, ...]         # globs for downstream business-logic files to trace into, for example managers and dao
    body: str


def _guide(path, meta: dict, body: str) -> Guide:
    detect = meta.get("detect", {}) or {}
    return Guide(
        id=str(meta.get("id", path.stem)),
        kind=str(meta.get("kind", "")).strip().lower(),
        language=str(meta.get("language", "")).strip().lower(),
        title=str(meta.get("title", path.stem)),
        detect_files=tuple(str(f) for f in detect.get("files", [])),
        detect_manifest=tuple(str(m).lower() for m in detect.get("manifest", [])),
        detect_imports=tuple(str(i) for i in detect.get("imports", [])),
        detect_content=tuple(str(c).lower() for c in detect.get("content", [])),
        entrypoint_files=tuple(str(g) for g in meta.get("entrypoint_files", [])),
        entrypoint_markers=tuple(str(m) for m in meta.get("entrypoint_markers", [])),
        logic_layers=tuple(str(g) for g in meta.get("logic_layers", [])),
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


def logic_layer_globs(guides: list[Guide]) -> tuple[str, ...]:
    """The downstream business-logic globs declared by a set of guides,
    deduplicated. These name where logic lives below the entrypoint, for example
    managers, controllers, dao, and services, so a trace does not stop at the view."""
    seen: dict[str, None] = {}
    for g in guides:
        for pat in g.logic_layers:
            seen.setdefault(pat, None)
    return tuple(seen)


def load_guides(languages_dir=LANGUAGES_DIR, frameworks_dir=FRAMEWORKS_DIR, protocols_dir=PROTOCOLS_DIR) -> list[Guide]:
    # kind comes from each guide's frontmatter, the single source of truth. The
    # directories are a convenience for humans and never decide kind, so the two
    # cannot drift.
    out: list[Guide] = []
    for directory in (languages_dir, frameworks_dir, protocols_dir):
        out += [_guide(path, meta, body) for path, meta, body in iter_md_docs(directory)]
    return out


def _matches(guide: Guide, files: list[str], manifest_text: str, source_text: str) -> bool:
    if any(fnmatch.fnmatch(f, pat) for pat in guide.detect_files for f in files):
        return True
    if any(m in manifest_text for m in guide.detect_manifest):     # dependency names, manifests only
        return True
    if any(i in source_text for i in guide.detect_imports):        # import markers, source only
        return True
    if any(c in source_text for c in guide.detect_content):        # content tokens, source only
        return True
    return False


def select_guides(files, *, manifest_text: str = "", source_text: str = "", guides: list[Guide] | None = None) -> list[Guide]:
    """The guides whose detect signals fire on the target, languages first then
    frameworks. `files` are the target's file paths. `manifest_text` is the
    dependency-manifest content, scanned only for dependency-name substrings, so a
    name like a framework's does not false-match a word in source. `source_text`
    is a source sample or a diff body, scanned for import markers and for
    language-neutral content tokens such as a protocol's wire fields."""
    pool = load_guides() if guides is None else guides
    file_list = list(files)
    man = manifest_text.lower()
    src = source_text.lower()
    return [g for g in pool if _matches(g, file_list, man, src)]
