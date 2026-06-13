"""A review domain: a self-contained body of security knowledge plus where it lives.

codejury reviews more than one kind of code, web today, smart contracts next. The
engine itself names no language, all the language and vulnerability knowledge is data
under a content root: `knowledge/`, `playbook/`, and `detection.yaml`. A `Domain` ties a
name to one such content root, and `ContentPaths` resolves the fixed file layout under
it. Selecting a domain swaps the whole knowledge set without touching the engine.

This module holds no path of its own and imports nothing from `codejury`, so the leaf
modules that only need resolved paths can depend on `ContentPaths` with no import cycle.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, kw_only=True)
class ContentPaths:
    """The fixed content layout under one domain's root, resolved to absolute paths.

    Mirrors the constants the engine has always read, so a caller given a `ContentPaths`
    reads the same files whether the domain is web or another."""
    knowledge: Path
    vulnerabilities_dir: Path
    languages_dir: Path
    frameworks_dir: Path
    protocols_dir: Path
    knowledge_index: Path
    methodology_file: Path
    slash_command_file: Path
    unit_review_file: Path
    severity_rubric_file: Path
    false_positive_traps_file: Path
    detection_file: Path


def content_paths(content_root: str | Path) -> ContentPaths:
    """Resolve the content layout under a domain root. The relative structure is the
    contract every domain follows, so a new domain is a directory in the same shape."""
    root = Path(content_root)
    knowledge = root / "knowledge"
    guides = knowledge / "guides"
    playbook = root / "playbook"
    return ContentPaths(
        knowledge=knowledge,
        vulnerabilities_dir=knowledge / "vulnerabilities",
        languages_dir=guides / "languages",
        frameworks_dir=guides / "frameworks",
        protocols_dir=guides / "protocols",
        knowledge_index=knowledge / "index.md",
        methodology_file=playbook / "methodology.md",
        slash_command_file=playbook / "slash-command.md",
        unit_review_file=playbook / "unit-review.md",
        severity_rubric_file=playbook / "severity-rubric.md",
        false_positive_traps_file=playbook / "false-positive-traps.md",
        detection_file=root / "detection.yaml",
    )


@dataclass(frozen=True, kw_only=True)
class Domain:
    """A named review domain bound to a content root. `paths` resolves its content."""
    name: str
    content_root: Path

    @property
    def paths(self) -> ContentPaths:
        return content_paths(self.content_root)
