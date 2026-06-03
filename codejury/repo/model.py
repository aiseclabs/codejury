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


def candidate_entrypoint_files(files, globs) -> list[str]:
    """The files matching any of `globs` (a guide's declared entrypoint-file
    patterns), in sorted order, deduplicated."""
    pats = tuple(globs)
    return [f for f in files if any(fnmatch.fnmatch(f, g) for g in pats)]
