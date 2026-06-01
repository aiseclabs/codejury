"""Verdict cache: determinism through content-addressed reuse (ROADMAP P0).

Invariant 2: the same input must yield the same verdicts. An ``AnalysisResult``
is stored under ``hash(normalized code + capability versions + orchestration)``,
so re-auditing unchanged code returns the recorded verdicts instead of querying
the model again (which can drift across model revisions even at temperature 0).

The key ingredients:

- **normalized code**: the artifact text with line endings and trailing
  whitespace normalized, so cosmetic reformatting alone does not miss the cache.
- **capability versions**: each in-scope capability's ``fingerprint`` (a hash
  of its knowledge), so editing a capability YAML invalidates affected entries.
- **orchestration**: strategy + model + token budget, since those change the
  verdict.

A failed run (``result.error`` set) is never cached, so a transient provider
error does not stick. ``--no-cache`` bypasses the layer entirely.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from codejury.domain.artifact import CodeArtifact
from codejury.domain.capability import Capability
from codejury.domain.result import AnalysisResult

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "codejury" / "verdicts"


def _normalize(code: str) -> str:
    lines = code.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return "\n".join(line.rstrip() for line in lines).strip("\n")


def verdict_key(
    artifact: CodeArtifact, capabilities: list[Capability], *, orchestration: str
) -> str:
    payload = {
        "kind": artifact.kind,
        "path": artifact.path,
        "code": _normalize(artifact.content),
        "context": _normalize(artifact.context),
        "capabilities": sorted(f"{c.id}@{c.fingerprint()}" for c in capabilities),
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
        with open(path, encoding="utf-8") as f:
            return AnalysisResult.from_dict(json.load(f))

    def put(self, key: str, result: AnalysisResult) -> None:
        if result.error:  # never cache a partial/failed run
            return
        self._dir.mkdir(parents=True, exist_ok=True)
        with open(self._dir / f"{key}.json", "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, ensure_ascii=False)
