"""RepoModel: a language-agnostic structural map of a repository.

Lists the repo's files (deterministic, zero model call, cacheable). It does not
parse code or enumerate framework routes: identifying the actual entrypoints is
left to the agent, guided by the matched language/framework guides
(`data/languages`, `data/frameworks`). The only deterministic help is flagging
*candidate* entrypoint files by the globs a guide declares (e.g. Django's
`*urls.py`), which is language-agnostic and keeps framework logic out of code.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

_SKIP_DIRS = frozenset({".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache"})


@dataclass(frozen=True, kw_only=True)
class RepoModel:
    root: str
    files: tuple[str, ...]


def _read_files(root: Path) -> tuple[str, ...]:
    """Relative paths of the files under root, skipping noise dirs and symlinks
    that escape the tree."""
    root = root.resolve()
    out: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        try:
            if not path.resolve().is_relative_to(root):
                continue  # symlink escaping the tree
        except OSError:
            continue
        out.append(str(rel))
    return tuple(sorted(out))


def build_repo_model_from_dir(root: str | Path) -> RepoModel:
    """Build a RepoModel by listing the files under a directory."""
    return RepoModel(root=str(root), files=_read_files(Path(root)))


def build_repo_model(root: str | Path, files) -> RepoModel:
    """Build a RepoModel from an iterable of relative paths (for tests / callers
    that already have the file list)."""
    return RepoModel(root=str(root), files=tuple(sorted(files)))


# source extensions whose content is scanned for a guide's entrypoint markers
_SCAN_EXT = frozenset({
    ".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".go", ".rb", ".java", ".kt",
    ".php", ".cs", ".scala", ".rs",
})
_SCAN_MAX_BYTES = 2_000_000

# test code is not an entrypoint, untrusted input does not enter through it
_TEST_DIRS = frozenset({"test", "tests", "__tests__", "__mocks__", "mocks", "fixtures", "testdata", "e2e"})


def _is_test_path(f: str) -> bool:
    parts = f.replace("\\", "/").split("/")
    if any(p in _TEST_DIRS for p in parts[:-1]):
        return True
    stem = parts[-1].rsplit(".", 1)[0].lower()
    return parts[-1] == "conftest.py" or stem.startswith("test_") or stem.endswith("_test") or stem.endswith(".test")


def _read_text(path: Path) -> str:
    try:
        if path.stat().st_size > _SCAN_MAX_BYTES:
            return ""
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def candidate_entrypoint_files(files, *, root=None, globs=(), markers=()) -> list[str]:
    """Files likely to define entrypoints. A file is a candidate when its path
    matches one of `globs`, or when `root` is given and its content contains one
    of `markers` such as a DRF `ViewSet` or a route registration. The marker scan
    is what recovers framework entrypoints that no filename glob would catch, and
    it stays data-driven because the markers come from the guide. Returns a sorted
    list with no duplicates."""
    globs = tuple(globs)
    markers = tuple(markers)
    base = Path(root) if root is not None else None
    out: list[str] = []
    for f in files:
        if _is_test_path(f):
            continue
        if any(fnmatch.fnmatch(f, g) for g in globs):
            out.append(f)
            continue
        if markers and base is not None and Path(f).suffix in _SCAN_EXT:
            text = _read_text(base / f)
            if text and any(m in text for m in markers):
                out.append(f)
    return out
