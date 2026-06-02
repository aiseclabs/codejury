"""CodeArtifact: the unit of code an agent analyzes.

Produced by a Source (diff hunk, file, function, repo chunk) and consumed by an
agent. It is cross-layer typed data, so it lives in ``domain`` rather than in
``sources``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ArtifactKind = Literal["diff", "file", "function", "repo", "api_endpoint", "repo_design"]


@dataclass(frozen=True, kw_only=True)
class CodeArtifact:
    kind: ArtifactKind
    path: str       # identifier used when building Evidence references
    content: str    # the diff/file/function text the agent analyzes
    # related code (e.g. cross-file call sites) shown to help trace data flow,
    # but not itself under review
    context: str = ""
