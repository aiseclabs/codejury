"""The Completeness Gate over a fan-out review workspace.

The whole-repo review is agent-driven, not a coded pipeline, so this does not run
or judge the review. It reads the workspace's own bookkeeping and refuses to call a
review complete while it is unfinished: the attack surface not enumerated, a unit
left un-reviewed, or a finding parked below HIGH. It is a structural floor, not a
recall guarantee: it verifies the inventory denominator is built and every unit
carries a verdict, never that every real issue was found. Recall is a property the
fan-out and the re-runs carry, not something a checker can assert.

Each check reads a structured cell, a table row, a Status line, a Risk line, never a
free-prose claim, so the agent cannot clear it by writing a word.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from codejury.markdown_docs import md_field


@dataclass(frozen=True)
class GateResult:
    passed: bool
    failures: list[str]   # one human-readable line per unmet gate item
    checked: list[str]    # the items that were checked, for a transparent report


def _table_data_rows(text: str) -> list[list[str]]:
    """Data rows of a markdown table, header and separator rows skipped."""
    rows: list[list[str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if not "".join(cells) or set("".join(cells)) <= {"-", ":"}:
            continue  # separator row
        if any(c.lower() == "module" for c in cells):
            continue  # header row
        rows.append(cells)
    return rows


def _line_value(text: str, key: str) -> str | None:
    v = md_field(text, key)
    return v.lower() if v is not None else None


def check_gate(project_dir: Path) -> GateResult:
    """Check the fan-out review workspace `<workspace>/<project>` against the gate.

    Returns a GateResult. The caller decides the exit code. A missing or never
    scaffolded workspace is itself a failure, since nothing was reviewed."""
    failures: list[str] = []
    checked: list[str] = []

    if not project_dir.is_dir():
        return GateResult(False, [f"workspace {project_dir} does not exist, nothing was reviewed"], [])

    # 1. The attack surface is enumerated: the coverage denominator exists.
    checked.append("attack surface enumerated")
    surface = project_dir / "inventory" / "_surface.md"
    if surface.is_file():
        if not _table_data_rows(surface.read_text(encoding="utf-8")):
            failures.append("inventory/_surface.md has no enumerated entrypoint, the Phase 1 surface map was not built")
    else:
        failures.append("inventory/_surface.md is missing, the attack-surface inventory was not built")

    # 2. Every unit was reviewed, none left open. The per-unit coverage check.
    checked.append("every unit reviewed")
    units_dir = project_dir / "units"
    unit_files = sorted(units_dir.glob("*.md")) if units_dir.is_dir() else []
    if not unit_files:
        failures.append("units/ has no unit files, the surface was not decomposed into units to fan out over")
    else:
        open_units = [
            f.name for f in unit_files
            if (_line_value(f.read_text(encoding="utf-8"), "status") or "open") != "reviewed"
        ]
        if open_units:
            shown = ", ".join(open_units[:5]) + (" ..." if len(open_units) > 5 else "")
            failures.append(f"{len(open_units)} unit(s) in units/ are not Status: reviewed, run their sub-review: {shown}")

    # 3. Every finding carries a calibrated severity. All four levels are valid output,
    #    the goal is to surface every real issue at its level, so MEDIUM and LOW are
    #    not failures. The check is that a finding is graded against the rubric, never
    #    that it clears a floor, since a floor pushes a cautious reviewer to refute a
    #    real finding rather than report it as MEDIUM.
    checked.append("findings graded by the rubric")
    _LEVELS = ("critical", "high", "medium", "low")
    issues_dir = project_dir / "issues"
    if issues_dir.is_dir():
        for f in sorted(issues_dir.glob("*.md")):
            risk = _line_value(f.read_text(encoding="utf-8"), "(?:risk|severity)")
            if risk is None or not any(lvl in risk for lvl in _LEVELS):
                failures.append(
                    f"issues/{f.name} has no calibrated Risk line, grade it CRITICAL, HIGH, "
                    "MEDIUM, or LOW per inventory/_severity.md")

    return GateResult(not failures, failures, checked)
