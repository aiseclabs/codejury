"""MockSource -- a Source that yields canned CodeArtifacts.

Used by the dry-run and tests so the pipeline has input without touching git or
the filesystem. Pass your own artifacts, or rely on the default illustrative diff.
"""

from __future__ import annotations

from codejury.domain.artifact import CodeArtifact
from codejury.sources.base import Source

_DEFAULT_DIFF = """\
+def store_password(pwd: str) -> str:
+    return hashlib.sha256(pwd.encode()).hexdigest()
"""


class MockSource(Source):
    def __init__(self, artifacts: list[CodeArtifact] | None = None) -> None:
        self._artifacts = artifacts if artifacts is not None else [
            CodeArtifact(kind="diff", path="auth.py", content=_DEFAULT_DIFF),
        ]

    def list_artifacts(self) -> list[CodeArtifact]:
        return list(self._artifacts)
