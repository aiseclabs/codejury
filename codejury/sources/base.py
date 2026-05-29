"""Source ABC.

A Source turns some input (a PR diff, a file, a repo, a function) into a list of
CodeArtifacts an agent can analyze. Returning a list rather than one artifact
lets a single source fan out (e.g. one artifact per changed hunk).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from codejury.domain.artifact import CodeArtifact


class Source(ABC):
    @abstractmethod
    def list_artifacts(self) -> list[CodeArtifact]: ...
