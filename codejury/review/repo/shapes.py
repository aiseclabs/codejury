"""Shared shapes and contracts for both Repo Review backends, the model reviewer in
`reviewer.py` and the agent reviewer in `agent.py`.

`Unit` is the worklist item both backends review. `gather` reads a unit's code into one
bounded block. `JSON_SHAPE` and `lens_line` are the output contract both backends emit and
parse. These live here so neither backend reaches into the other for a shared shape, and so
the core `Unit` type does not sit inside one backend's module.
"""

from __future__ import annotations

from dataclasses import dataclass

from codejury.review.repo.paths import safe_repo_path

_GATHER_PER_FILE = 24_000
_GATHER_TOTAL = 120_000


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


def gather(unit: Unit) -> str:
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


JSON_SHAPE = (
    '{"findings": [{"title": "...", "category": "<class id>", '
    '"symbol": "exact function or method name the finding lives in, identifier only", '
    '"endpoint": "METHOD /path or empty", "file": "path", "line": 0, '
    '"severity": "CRITICAL|HIGH|MEDIUM|LOW", "evidence": "controlling fact at file:line", '
    '"status": "confirmed|blocked"}]}'
)


def lens_line(lens: str) -> str:
    """An empty lens reviews every class, a named lens leads with that class but still
    reports the others, so a focused pass never narrows recall."""
    if not lens:
        return "Review for every high-impact class.\n\n"
    return (f"This pass LEADS WITH THE {lens.upper()} LENS: prioritize finding {lens} "
            f"issues across this unit, while still reporting any other class you see.\n\n")
