"""The per-unit reviewer: review one unit deeply and return its candidate findings.

This is the seam between the coded orchestration and the model judgment. The
orchestration owns what is mechanical, the worklist, the passes, the lenses, the
union, the convergence. The reviewer owns the one thing that is judgment, reading a
small slice of code deeply and deciding what is exploitable. It is an interface so
the judgment backend can change, a single grounded model call today, a tool-using
agent later, without touching the orchestration.

The default `ModelReviewer` makes one `provider.complete` call per unit per pass: it
gathers the unit's code, prepends the shared mandate and the severity rubric, leads
with the pass's lens, and parses the returned JSON into `Candidate`s. It names no
language, the unit's files come from the data-driven worklist.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from codejury.domains.base import ContentPaths
from codejury.json_parse import require_json_object
from codejury.providers.base import Message, Provider
from codejury.resources import SEVERITY_RUBRIC_FILE, UNIT_REVIEW_FILE
from codejury.review.repo.paths import is_unsafe_rel, safe_repo_path
from codejury.review.repo.shapes import JSON_SHAPE, lens_line
from codejury.review.repo.union import Candidate


class RepoReviewError(RuntimeError):
    """A unit review reply could not be parsed into a result, so it is a failed review,
    not an empty one. Raised instead of returning no findings, mirroring the diff
    engine's AuditError, so the pass-loop counts the failure and never reads an unusable
    reply such as a refusal or an error page as a clean unit."""


_GATHER_PER_FILE = 24_000
_GATHER_TOTAL = 120_000

# a cap on the per-unit facts block, so a unit owning many files still leads with code, not
# a flood of facts. Per-unit facts are already scoped to the unit's files, so this is a
# guard against a unit that owns many files, set above the largest single contract's facts
# so a unit of one file is never truncated, not the head truncation a global dump needs
_FACTS_PER_UNIT = 16_000


@dataclass(frozen=True, kw_only=True)
class Unit:
    """One unit of the worklist: the files it owns plus the files it traces into. `span`,
    when set, is the char window of the first owned file this unit reviews, so a file too
    large for one call is split across sibling units instead of being silently truncated.
    `fragments`, when set, are `(file, start, end)` source slices this unit reviews instead
    of whole files, so a call-path unit co-locates a function and its call-graph neighborhood
    rather than a char window. `files` still names the source files for facts grounding and
    coverage bookkeeping."""
    name: str
    root: str
    files: tuple[str, ...]
    span: tuple[int, int] | None = None
    fragments: tuple[tuple[str, int, int], ...] = ()


def candidates_from_obj(obj: object) -> list[Candidate]:
    """Map a model reply's `findings` list onto Candidates, tolerant of junk."""
    if not isinstance(obj, dict) or not isinstance(obj.get("findings"), list):
        return []
    out: list[Candidate] = []
    for d in obj["findings"]:
        if not isinstance(d, dict):
            continue
        title = str(d.get("title") or d.get("description") or "").strip()
        if not title:
            continue
        line = d.get("line")
        sev = str(d.get("severity", "")).strip().upper()
        rel = str(d.get("file", "")).strip()
        file = "" if is_unsafe_rel(rel) else rel
        out.append(Candidate(
            title=title,
            category=str(d.get("category", "")).strip(),
            endpoint=str(d.get("endpoint") or d.get("source") or "").strip(),
            symbol=str(d.get("symbol") or "").strip(),
            file=file,
            line=line if isinstance(line, int) and not isinstance(line, bool) and line >= 1 else None,
            severity=sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM",
            evidence=str(d.get("evidence", "")).strip(),
            status="blocked" if str(d.get("status", "")).strip().lower() == "blocked" else "confirmed",
        ))
    return out


class UnitReviewer(ABC):
    @abstractmethod
    def review(self, unit: Unit, lens: str, *, shared_context: str = "") -> list[Candidate]:
        """Deeply review one unit through one lens, return its candidate findings."""


def _gather_fragments(unit: Unit) -> str:
    """Assemble a call-path unit from its source fragments, the function bodies the packer
    co-located, so the model sees the path in one focused window. Each fragment is labeled
    with its file and char range, the same header form a block of a whole file uses."""
    parts: list[str] = []
    total = 0
    for rel, start, end in unit.fragments:
        path = safe_repo_path(unit.root, rel)
        if path is None:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        seg = text[start:end]
        block = f"# file: {rel} chars {start}-{end}\n{seg}"
        parts.append(block)
        total += len(block)
        if total >= _GATHER_TOTAL:
            break
    return "\n\n".join(parts)


def _gather(unit: Unit) -> str:
    """Pack the unit's files into one bounded block, so a single call can trace
    across them without live file access. Unreadable or oversized files are skipped."""
    if unit.fragments:
        return _gather_fragments(unit)
    parts: list[str] = []
    total = 0
    for i, rel in enumerate(unit.files):
        path = safe_repo_path(unit.root, rel)
        if path is None:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if i == 0 and unit.span is not None:
            # this unit owns one char window of a file too large for a single call, so it
            # reviews just that slice and sibling units cover the rest, no silent truncation
            start, end = unit.span
            header = f"# file: {rel} chars {start}-{end}"
            text = text[start:end]
        else:
            header = f"# file: {rel}"
            text = text[:_GATHER_PER_FILE]
        block = f"{header}\n{text}"
        parts.append(block)
        total += len(block)
        if total >= _GATHER_TOTAL:
            break
    return "\n\n".join(parts)


_SYSTEM = (
    "You are a senior application security engineer reviewing one slice of a codebase. "
    "Report only real, evidenced findings, each graded by the rubric and located at a "
    "file:line. Respond with a single JSON object and nothing else."
)


class ModelReviewer(UnitReviewer):
    """Default reviewer: one grounded model call per unit per pass."""

    def __init__(self, *, provider: Provider, model: str, max_tokens: int = 4096,
                 content: ContentPaths | None = None,
                 facts_by_file: dict[str, str] | None = None) -> None:
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens
        mandate_file = content.unit_review_file if content else UNIT_REVIEW_FILE
        rubric_file = content.severity_rubric_file if content else SEVERITY_RUBRIC_FILE
        self._mandate = mandate_file.read_text(encoding="utf-8")
        self._rubric = rubric_file.read_text(encoding="utf-8")
        # per-file facts blocks, keyed by a path relative to the repo, see Facts.data["by_file"]. A
        # basename index backs a loose match when a unit's path and the facts key differ only
        # by a leading directory. Empty when the domain binds no facts backend, so web is
        # unchanged
        self._facts_by_file = facts_by_file or {}
        self._facts_by_base: dict[str, str] = {}
        for rel, block in self._facts_by_file.items():
            self._facts_by_base.setdefault(rel.rsplit("/", 1)[-1], block)

    @property
    def label(self) -> str:
        """The model name, used to tag which model surfaced a finding for the consensus signal."""
        return self._model

    def _facts_for(self, unit: Unit) -> str:
        """The facts for the files this unit owns, so a unit reviewing one slice of a large
        file still carries that file's whole call graph, the cross-slice signal."""
        if not self._facts_by_file:
            return ""
        seen: set[str] = set()
        blocks: list[str] = []
        total = 0
        for rel in unit.files:
            block = self._facts_by_file.get(rel) or self._facts_by_base.get(rel.rsplit("/", 1)[-1])
            if not block or block in seen:
                continue
            seen.add(block)
            blocks.append(block)
            total += len(block)
            if total >= _FACTS_PER_UNIT:
                break
        text = "\n".join(blocks)
        return text[:_FACTS_PER_UNIT] if len(text) > _FACTS_PER_UNIT else text

    def review(self, unit: Unit, lens: str, *, shared_context: str = "") -> list[Candidate]:
        unit_facts = self._facts_for(unit)
        prompt = (
            f"{self._mandate}\n\n---\nSeverity rubric:\n{self._rubric}\n\n---\n"
            f"{lens_line(lens)}"
            + (f"Stack and authorization model:\n{shared_context}\n\n" if shared_context else "")
            + (f"Contract facts for this unit, tool-extracted, the call graph and storage "
               f"the slice below may not show in full:\n{unit_facts}\n\n" if unit_facts else "")
            + f"Unit `{unit.name}`, the code to review:\n```\n{_gather(unit)}\n```\n\n"
            f"Respond with a single JSON object exactly like:\n{JSON_SHAPE}"
        )
        result = self._provider.complete(
            system=_SYSTEM,
            messages=[Message(role="user", content=prompt)],
            model=self._model,
            max_tokens=self._max_tokens,
            cache=True,
        )
        obj = require_json_object(
            result.text, required_key="findings", error=RepoReviewError,
            message="the unit review reply had no JSON object, or a JSON object without a "
                    "findings key, so it is a failed review rather than a clean unit",
        )
        return candidates_from_obj(obj)
