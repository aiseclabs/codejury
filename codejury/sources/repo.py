"""RepoSource -- walk a repository into CodeArtifacts, one per file (chunked).

Selects files by extension, skips noise directories (.git, virtualenvs, caches),
and runs each file through a Chunker so large files fit the model's context
window. Artifact paths are relative to the repo root.
"""

from __future__ import annotations

from pathlib import Path

from codejury.domain.artifact import CodeArtifact
from codejury.sources.base import Source
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
    ) -> None:
        self._root = Path(root)
        self._extensions = extensions
        self._chunker = chunker or Chunker()
        self._skip_dirs = skip_dirs

    def list_artifacts(self) -> list[CodeArtifact]:
        artifacts: list[CodeArtifact] = []
        for path in sorted(self._root.rglob("*")):
            if not path.is_file() or path.suffix not in self._extensions:
                continue
            if any(part in self._skip_dirs for part in path.relative_to(self._root).parts):
                continue
            rel = path.relative_to(self._root).as_posix()
            content = path.read_text(encoding="utf-8", errors="replace")
            for chunk_path, chunk_content in self._chunker.split(rel, content):
                artifacts.append(CodeArtifact(kind="repo", path=chunk_path, content=chunk_content))
        return artifacts
