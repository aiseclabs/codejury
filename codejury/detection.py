"""File and path classification config, loaded from `detection.yaml`.

What the engine treats as a source file, a dependency manifest, a noise
directory, or test code, across ecosystems. Kept in data so the implementation
enumerates no language itself: adding a language is a data edit, not a code
change. This is distinct from a guide's stack detection in `guides.py`, which
decides which language, framework, or protocol applies.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from functools import lru_cache

import yaml

from codejury.resources import DETECTION_FILE


@dataclass(frozen=True)
class Detection:
    skip_dirs: frozenset[str]            # directory names that are noise, never walked
    source_extensions: frozenset[str]    # extensions whose content is scanned for markers
    config_extensions: frozenset[str]    # config extensions also sampled when detecting the stack
    manifests: tuple[str, ...]           # dependency-manifest filenames read to detect the stack
    test_dirs: frozenset[str]            # directory segments that mark test code
    test_name_patterns: tuple[str, ...]  # filename globs that mark a test file

    @property
    def detection_extensions(self) -> frozenset[str]:
        """Source plus config, the files sampled when detecting the stack."""
        return self.source_extensions | self.config_extensions

    def is_test_path(self, path: str) -> bool:
        """True when a path is test code, by a test directory segment or a
        test-file naming convention. Conservative, so a production file is not
        suppressed."""
        parts = path.replace("\\", "/").split("/")
        if any(p in self.test_dirs for p in parts[:-1]):
            return True
        name = parts[-1].lower()
        return any(fnmatch.fnmatch(name, pat) for pat in self.test_name_patterns)


@lru_cache(maxsize=1)
def load_detection() -> Detection:
    data = yaml.safe_load(DETECTION_FILE.read_text(encoding="utf-8")) or {}
    return Detection(
        skip_dirs=frozenset(data.get("skip_dirs", [])),
        source_extensions=frozenset(data.get("source_extensions", [])),
        config_extensions=frozenset(data.get("config_extensions", [])),
        manifests=tuple(data.get("manifests", [])),
        test_dirs=frozenset(data.get("test_dirs", [])),
        test_name_patterns=tuple(data.get("test_name_patterns", [])),
    )
