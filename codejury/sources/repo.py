"""RepoSource: walk a repository into CodeArtifacts, one per file, chunked.

Selects files by extension, skips noise directories (.git, virtualenvs, caches),
and runs each file through a Chunker so large files fit the model's context
window. Artifact paths are relative to the repo root.
"""

from __future__ import annotations

from pathlib import Path

from codejury.domain.artifact import CodeArtifact
from codejury.sources.base import Source
from codejury.sources.callers import caller_context, callee_context
from codejury.sources.chunker import Chunker

_SKIP_DIRS = frozenset({".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache"})


class RepoSource(Source):
    def __init__(
        self,
        root: str | Path,
        *,
        extensions: tuple[str, ...] = (".py",),
        chunker: Chunker | None = None,
        skip_dirs: frozenset[str] = _SKIP_DIRS,
        with_callers: bool = False,
        with_callees: bool = False,
    ) -> None:
        self._root = Path(root)
        self._extensions = extensions
        self._chunker = chunker or Chunker()
        self._skip_dirs = skip_dirs
        self._with_callers = with_callers
        self._with_callees = with_callees

    def list_artifacts(self) -> list[CodeArtifact]:
        files = self._read_files()
        artifacts: list[CodeArtifact] = []
        for rel, content in sorted(files.items()):
            context = self._context(rel, files)
            for chunk_path, chunk_content in self._chunker.split(rel, content):
                artifacts.append(
                    CodeArtifact(kind="repo", path=chunk_path, content=chunk_content, context=context)
                )
        return artifacts

    def _context(self, rel: str, files: dict[str, str]) -> str:
        parts = []
        if self._with_callers:
            callers = caller_context(rel, files)
            if callers:
                parts.append("Callers (where this file's functions are used):\n" + callers)
        if self._with_callees:
            callees = callee_context(rel, files)
            if callees:
                parts.append("Callees (functions this file calls, defined elsewhere):\n" + callees)
        return "\n\n".join(parts)

    def _read_files(self) -> dict[str, str]:
        files: dict[str, str] = {}
        root = self._root.resolve()
        for path in self._root.rglob("*"):
            if not path.is_file() or path.suffix not in self._extensions:
                continue
            if any(part in self._skip_dirs for part in path.relative_to(self._root).parts):
                continue
            # don't follow a symlink that escapes the repo (e.g. x.py -> /etc/passwd)
            if not path.resolve().is_relative_to(root):
                continue
            rel = path.relative_to(self._root).as_posix()
            files[rel] = path.read_text(encoding="utf-8", errors="replace")
        return files
