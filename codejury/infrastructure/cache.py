"""Verdict cache: determinism through content-addressed reuse (ROADMAP P0).

Invariant 2: the same input must yield the same verdicts. An ``AnalysisResult``
is stored under ``hash(normalized code + skill versions + orchestration)``, so
re-auditing unchanged code returns the recorded verdicts instead of querying the
model again (which can drift across model revisions even at temperature 0).

The key ingredients:

- **normalized code**: the artifact text with line endings and trailing
  whitespace normalized, so cosmetic reformatting alone does not miss the cache.
- **skill versions**: each in-scope skill's ``fingerprint`` (a hash of its
  manifest and playbook), so editing a skill invalidates affected entries.
- **orchestration**: strategy + model + token budget, since those change the
  verdict.

A failed run (``result.error`` set) is never cached, so a transient provider
error does not stick. ``--no-cache`` bypasses the layer entirely.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Protocol, Sequence

from codejury.domain.artifact import CodeArtifact
from codejury.domain.result import AnalysisResult

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "codejury" / "verdicts"

# Bump when the cached payload shape changes, so entries written by an older
# codejury are not read back under a changed schema. It is folded into the key.
_SCHEMA = "2"


class Fingerprinted(Protocol):
    """A check unit with a stable id and a content fingerprint (a Skill)."""

    id: str

    def fingerprint(self) -> str: ...


def normalize_code(code: str) -> str:
    """Line-ending and trailing-whitespace normalized code, so cosmetic
    reformatting alone does not miss a content-addressed cache. Shared by the
    verdict cache and the selection cache."""
    lines = code.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return "\n".join(line.rstrip() for line in lines).strip("\n")


def verdict_key(
    artifact: CodeArtifact, units: Sequence[Fingerprinted], *, orchestration: str
) -> str:
    payload = {
        "schema": _SCHEMA,
        "kind": artifact.kind,
        "path": artifact.path,
        "code": normalize_code(artifact.content),
        "context": normalize_code(artifact.context),
        "skills": sorted(f"{u.id}@{u.fingerprint()}" for u in units),
        "orchestration": orchestration,
    }
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class VerdictCache:
    """A content-addressed store of ``AnalysisResult`` keyed by ``verdict_key``.

    Disk-backed (one JSON file per key) so reproducibility holds across separate
    CLI invocations, not just within one process.
    """

    def __init__(self, directory: str | Path = DEFAULT_CACHE_DIR) -> None:
        self._dir = Path(directory)

    def get(self, key: str) -> AnalysisResult | None:
        path = self._dir / f"{key}.json"
        if not path.exists():
            return None
        try:
            with open(path, encoding="utf-8") as f:
                return AnalysisResult.from_dict(json.load(f))
        except (ValueError, OSError):  # corrupt or half-written entry: treat as a miss
            return None

    def put(self, key: str, result: AnalysisResult) -> None:
        if result.error:  # never cache a partial/failed run
            return
        self._dir.mkdir(parents=True, exist_ok=True)
        path = self._dir / f"{key}.json"
        # write to a temp file then atomically rename, so a concurrent reader never
        # sees a half-written entry
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, ensure_ascii=False)
        os.replace(tmp, path)
