"""A review domain: a self-contained body of security knowledge plus where it lives.

codejury reviews more than one kind of code, web today, smart contracts next. The
engine itself names no language, all the language and vulnerability knowledge is data
under a content root: `knowledge/`, `playbook/`, and `detection.yaml`. A `Domain` ties a
name to one such content root, and `ContentPaths` resolves the fixed file layout under
it. Selecting a domain swaps the whole knowledge set without touching the engine.

It also declares the tool-backed seams a domain may bind, `FactsBackend` and
`SourceLoader`, as abstract interfaces. The interfaces name no tool, so a concrete
backend such as a Slither facts extractor or a block-explorer loader lives in its own
domain package behind an optional dependency, and a domain without one falls back to the
engine's own heuristics.

This module holds no path of its own and imports nothing from `codejury`, so the leaf
modules that only need resolved paths or these interfaces can depend on it with no import
cycle.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True, kw_only=True)
class ContentPaths:
    """The fixed content layout under one domain's root, resolved to absolute paths.

    The same fixed layout for every domain, so a caller given a `ContentPaths` reads the
    same files whether the domain is web or another."""
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
    """A named review domain: where its content lives plus the review strategy that is
    data, not engine logic. `lenses` rotate the repo-review passes, and the diff focus and
    do-not-report blocks lead the diff prompt. The engine reads these from the selected
    domain rather than naming any of them itself, so a new domain is the data here plus a
    content root. Severity is the model's, graded against the domain's rubric markdown, so
    it lives in that rubric and the verifier, not in a field here."""
    name: str
    content_root: Path
    lenses: tuple[str, ...]
    diff_focus: str
    diff_do_not_report: str
    # the optional facts backend that grounds repo review, None when the domain has none,
    # so the engine falls back to its own heuristics
    facts_backend: FactsBackend | None = None
    # dedup granularity for repo review. The web default keeps the endpoint in the key, so
    # one class on two HTTP routes is two findings to fix. A domain whose endpoint is a
    # function sharing a helper sets this True to dedup by file and class, since the same
    # root cause surfaces at every caller and is one finding, not one per function.
    dedup_by_file: bool = False

    @property
    def paths(self) -> ContentPaths:
        return content_paths(self.content_root)


class BackendUnavailable(RuntimeError):
    """A tool-backed seam was asked to work but its external tool is not installed. Raised,
    never swallowed into an empty result, so a missing toolchain is a loud failure and not a
    silently clean review, invariant 4."""


@dataclass(frozen=True, kw_only=True)
class Facts:
    """Deterministic, tool-extracted facts about a source tree, used to ground model review.
    `summary` is prompt-ready text the engine threads into shared context, `data` is the
    structured payload, such as a call graph a backend uses for unit packing. Empty facts
    mean no backend ran, the engine falls back to its own heuristics.

    A backend may also fill `data["by_file"]`, a generic convention the engine reads: a map
    from a source path relative to the repo to a prompt-ready facts block for that file. When set,
    the engine grounds each unit with only the facts for the files it owns, so a large file
    split into slices still carries its whole call graph, the cross-slice signal a flat,
    truncated global dump loses. The map is data the domain fills, the engine names no
    contract or function, it only indexes by the unit's files."""
    summary: str = ""
    data: dict = field(default_factory=dict)

    @property
    def empty(self) -> bool:
        return not self.summary and not self.data


class FactsBackend(ABC):
    """Extracts deterministic facts from a source tree to ground model review. A domain may
    bind one, the engine falls back to its heuristics when none is available, so facts are a
    precision and packing aid, not a hard requirement."""

    @abstractmethod
    def available(self) -> bool:
        """Whether the backing tool is installed, so a caller can fall back rather than fail
        when facts are optional."""

    @abstractmethod
    def extract(self, root: str | Path) -> Facts:
        """Extract facts from the source tree at root. Raise BackendUnavailable when the
        tool is absent rather than returning empty facts that would mask a missing
        toolchain."""


class SourceLoader(ABC):
    """Materializes review source into a local tree. The web domain reviews a checkout in
    place, another domain may fetch from a host or a block explorer. A domain may bind one,
    the CLI passes a local path directly when none is set."""

    @abstractmethod
    def available(self) -> bool:
        """Whether the backing tool or client is installed."""

    @abstractmethod
    def fetch(self, ref: str, dest: str | Path) -> Path:
        """Materialize the source named by ref under dest and return the review root. Raise
        BackendUnavailable when the backing tool or client is absent."""
