"""Knowledge coverage: scan the knowledge tree and cross it against the registry, so a
vulnerability class or a guide that no eval exercises is a visible gap, not a silent one.

Knowledge is data and the engine is generic, invariant 1. This module makes that
measurable. For each knowledge file it counts the positive and safe diff cases and the repo
planted and safe entries that exercise it, split by public and private provenance, and it
reports the gate problems the doc defines: a vulnerability with no positive or no safe diff
case, a benchmark reference that resolves to no real file, and an answer key entry that
names no knowledge at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from codejury.resources import LANGUAGES_DIR, VULNERABILITIES_DIR
from evals import registry
from evals.schema import knowledge_refs, load_answer_key
from evals.scorers.match import category_of

_GUIDES_DIR = LANGUAGES_DIR.parent


@dataclass(frozen=True, kw_only=True)
class KnowledgeItem:
    """One knowledge file the matrix tracks, addressed by its namespaced ref."""
    ref: str        # vuln:<id> or guide:<path>, the form a benchmark references
    kind: str       # vulnerability or guide
    path: Path


@dataclass(kw_only=True)
class Coverage:
    """How much eval evidence exercises one knowledge item, by source and provenance."""
    item: KnowledgeItem
    diff_positive: int = 0
    diff_safe: int = 0
    repo_planted: int = 0
    repo_safe: int = 0
    public: int = 0
    private: int = 0

    @property
    def covered(self) -> bool:
        return bool(self.diff_positive or self.diff_safe or self.repo_planted or self.repo_safe)


@dataclass(frozen=True, kw_only=True)
class CoverageProblem:
    """A gate-facing coverage gap. kind is one of missing-positive, missing-safe,
    unresolved-reference, entry-without-knowledge. unresolved-reference is a broken
    benchmark, the rest are gaps the case library should fill."""
    kind: str
    ref: str
    detail: str


def scan_knowledge() -> dict[str, KnowledgeItem]:
    """Every vulnerability class and guide in the package, keyed by namespaced ref. The
    guide ref mirrors its path under guides/, languages/python and frameworks/python/fastapi,
    the exact form a benchmark or an answer key references."""
    items: dict[str, KnowledgeItem] = {}
    for f in sorted(VULNERABILITIES_DIR.glob("*.md")):
        ref = f"vuln:{f.stem}"
        items[ref] = KnowledgeItem(ref=ref, kind="vulnerability", path=f)
    for f in sorted(_GUIDES_DIR.rglob("*.md")):
        rel = f.relative_to(_GUIDES_DIR).with_suffix("").as_posix()
        ref = f"guide:{rel}"
        items[ref] = KnowledgeItem(ref=ref, kind="guide", path=f)
    return items


def _diff_case_refs() -> list[tuple[str, bool, tuple[str, ...], str]]:
    """Each shipped diff case as name, is_positive, knowledge refs, provenance. A positive
    case attributes to its category as a vulnerability ref. A safe case carries no category,
    so it attributes to nothing until the case library names its knowledge, the gap the
    coverage matrix surfaces. The shipped cases are public, they live in this repo."""
    from evals.diff_cases import CASES

    rows: list[tuple[str, bool, tuple[str, ...], str]] = []
    for name, category, _ in CASES:
        if category:
            rows.append((name, True, (f"vuln:{category_of(category)}",), "public"))
        else:
            rows.append((name, False, (), "public"))
    return rows


def coverage_matrix() -> dict[str, Coverage]:
    """Cross every knowledge item against the diff cases and the repo benchmarks the
    registry sees, tallying how each is exercised. A ref that no knowledge file backs is
    not counted here, it is reported as an unresolved-reference problem instead."""
    items = scan_knowledge()
    cov = {ref: Coverage(item=it) for ref, it in items.items()}

    for _, is_positive, refs, provenance in _diff_case_refs():
        for ref in refs:
            c = cov.get(ref)
            if c is None:
                continue
            if is_positive:
                c.diff_positive += 1
            else:
                c.diff_safe += 1
            setattr(c, provenance, getattr(c, provenance) + 1)

    for bench in registry.all_benchmarks().values():
        key = load_answer_key(bench.answer_key)
        for entry in key.planted:
            for ref in entry.knowledge:
                c = cov.get(ref)
                if c is None:
                    continue
                c.repo_planted += 1
                setattr(c, bench.provenance, getattr(c, bench.provenance) + 1)
        for entry in key.safe:
            for ref in entry.knowledge:
                c = cov.get(ref)
                if c is None:
                    continue
                c.repo_safe += 1
                setattr(c, bench.provenance, getattr(c, bench.provenance) + 1)
    return cov


def _all_referenced() -> list[tuple[str, str]]:
    """Every knowledge ref any benchmark names, manifest level and per entry, paired with a
    where label, so an unresolved one can be reported against its source."""
    refs: list[tuple[str, str]] = []
    for bench in registry.all_benchmarks().values():
        for ref in knowledge_refs(bench.knowledge):
            refs.append((ref, f"benchmark '{bench.id}' manifest"))
        key = load_answer_key(bench.answer_key)
        for entry in (*key.planted, *key.safe):
            for ref in entry.knowledge:
                refs.append((ref, f"benchmark '{bench.id}' entry '{entry.id}'"))
    return refs


def coverage_problems(cov: dict[str, Coverage] | None = None) -> list[CoverageProblem]:
    """The gate-facing gaps, in a stable order. Every vulnerability needs a positive and a
    safe diff case, every referenced knowledge file must exist, and every answer key entry
    should name at least one knowledge item, the rules from the design doc."""
    cov = coverage_matrix() if cov is None else cov
    problems: list[CoverageProblem] = []

    for ref, c in sorted(cov.items()):
        if c.item.kind != "vulnerability":
            continue
        if not c.diff_positive:
            problems.append(CoverageProblem(kind="missing-positive", ref=ref,
                                            detail="no positive diff case for this vulnerability class"))
        if not c.diff_safe:
            problems.append(CoverageProblem(kind="missing-safe", ref=ref,
                                            detail="no safe diff case to guard the false positive on this class"))

    known = set(scan_knowledge())
    for ref, where in _all_referenced():
        if ref not in known:
            problems.append(CoverageProblem(kind="unresolved-reference", ref=ref,
                                            detail=f"{where} references {ref}, which matches no knowledge file"))

    for bench in registry.all_benchmarks().values():
        key = load_answer_key(bench.answer_key)
        for entry in (*key.planted, *key.safe):
            if not entry.knowledge:
                problems.append(CoverageProblem(kind="entry-without-knowledge", ref=entry.id,
                                                detail=f"benchmark '{bench.id}' entry '{entry.id}' names no knowledge"))
    return problems


def format_matrix(cov: dict[str, Coverage], problems: list[CoverageProblem]) -> str:
    """A plain table of coverage by knowledge item, then the gap list. Uncovered files are
    the point, they name what the case library still has to reach."""
    rows = sorted(cov.values(), key=lambda c: (c.item.kind, c.item.ref))
    lines = ["=== knowledge coverage ===",
             f"  {'knowledge':52} diff+  diff-  repo+  repo-  prov"]
    for c in rows:
        prov = "/".join(p for p, n in (("pub", c.public), ("priv", c.private)) if n) or "-"
        flag = "" if c.covered else "  UNCOVERED"
        lines.append(f"  {c.item.ref:52} {c.diff_positive:>4}  {c.diff_safe:>4}  "
                     f"{c.repo_planted:>4}  {c.repo_safe:>4}  {prov}{flag}")
    uncovered = sum(1 for c in rows if not c.covered)
    lines.append(f"  {uncovered} of {len(rows)} knowledge files have no eval coverage")
    if problems:
        lines.append("")
        lines.append(f"=== coverage problems ({len(problems)}) ===")
        for p in problems:
            lines.append(f"  [{p.kind}] {p.ref}  {p.detail}")
    return "\n".join(lines)
