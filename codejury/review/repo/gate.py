"""The Completeness Gate as a mechanical check over a review workspace.

The whole-repo review is agent-driven, not a coded pipeline, so this does not run
or judge the review. It only reads the workspace's own bookkeeping and refuses to
call a review complete while that bookkeeping is unfinished, the failure that lets
a one-round run pass as clean. It is a structural floor, not a recall guarantee:
it verifies the ledger is filled, never that every real issue was found. Recall is
a multi-pass property the rounds and re-runs carry, not something a checker can
assert.

Each check reads a structured cell, a table Status column, a bullet marker, a Risk
line, never a free-prose claim, so the agent cannot clear it by writing a word.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class GateResult:
    passed: bool
    failures: list[str]   # one human-readable line per unmet gate item
    checked: list[str]    # the items that were checked, for a transparent report


def _table_status_cells(text: str) -> list[str]:
    """The Status column of every data row in the coverage ledger's markdown table.

    The ledger table is `| Sweep | Enumerates | Status | Verdict table |`, so the
    Status is the third cell. Header and separator rows are skipped. Reading the
    cell, not a substring of the file, keeps the prose that names 'partial' in the
    instructions from tripping the check."""
    cells: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        parts = [c.strip() for c in line.strip("|").split("|")]
        if len(parts) < 4:
            continue
        status = parts[2].lower()
        if status in ("status", "") or set(parts[2]) <= {"-", ":", " "}:
            continue  # header or separator row
        cells.append(status)
    return cells


def _blank_negative_rows(text: str) -> int:
    """Count data rows in the negatives ledger with a blank Attack or Verdict cell.

    The ledger is `| Candidate | Controlling fact | Attack | Verdict |`, so a row is
    audited only when all four cells are non-empty. Header and separator rows, and
    the empty ledger, do not count."""
    blank = 0
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        parts = [c.strip() for c in line.strip("|").split("|")]
        if len(parts) < 4:
            continue
        joined = " ".join(parts).lower()
        if "candidate" in joined and "verdict" in joined:
            continue  # header row
        if set("".join(parts)) <= {"-", ":"}:
            continue  # separator row
        if any(not parts[i] for i in range(4)):
            blank += 1
    return blank


def _risk_value(text: str) -> str | None:
    """The Risk or Severity value from an issue write-up, lowercased, or None."""
    m = re.search(r"(?im)^\s*-?\s*(?:risk|severity)\s*:\s*(.+?)\s*$", text)
    return m.group(1).lower() if m else None


def check_gate(project_dir: Path) -> GateResult:
    """Check the review workspace `<workspace>/<project>` against the gate.

    Returns a GateResult; the caller decides the exit code. A missing or never
    scaffolded workspace is itself a failure, since nothing was reviewed."""
    failures: list[str] = []
    checked: list[str] = []

    if not project_dir.is_dir():
        return GateResult(False, [f"workspace {project_dir} does not exist, nothing was reviewed"], [])

    # 1. Every entrypoint is resolved, none left unreviewed.
    checked.append("entrypoints resolved (no ❌)")
    inv = project_dir / "entrypoints" / "_entrypoints.md"
    if inv.is_file():
        open_count = sum(
            1 for ln in inv.read_text(encoding="utf-8").splitlines()
            if re.match(r"\s*-\s*❌", ln)
        )
        if open_count:
            failures.append(f"{open_count} entrypoint(s) still ❌ in entrypoints/_entrypoints.md, resolve or clear each")
    else:
        failures.append("entrypoints/_entrypoints.md is missing, the attack-surface inventory was not built")

    # 2. Every coverage sweep is done or n/a, none todo or partial.
    checked.append("coverage sweeps done (none todo/partial)")
    cov = project_dir / "analysis" / "_coverage.md"
    if cov.is_file():
        unfinished = [s for s in _table_status_cells(cov.read_text(encoding="utf-8")) if s in ("todo", "partial")]
        if unfinished:
            failures.append(
                f"{len(unfinished)} sweep(s) still {'/'.join(sorted(set(unfinished)))} in analysis/_coverage.md, "
                "drive each to done or n/a with a reason")
    else:
        failures.append("analysis/_coverage.md is missing, the per-class sweep ledger was not kept")

    # 3. At least two rounds were logged; one round does not find the deep classes.
    checked.append("multiple rounds logged")
    rounds = project_dir / "analysis" / "_rounds.md"
    if rounds.is_file():
        n = len(re.findall(r"(?im)^##\s+Round\b", rounds.read_text(encoding="utf-8")))
        if n < 2:
            failures.append(f"only {n} round logged in analysis/_rounds.md, a single round rarely reaches the deep classes")
    else:
        failures.append("analysis/_rounds.md is missing, the round ledger was not kept")

    # 4. Every recorded negative verdict was audited, no row left half-filled.
    checked.append("negative-verdict audit complete")
    neg = project_dir / "analysis" / "_negatives.md"
    if neg.is_file():
        unfinished = _blank_negative_rows(neg.read_text(encoding="utf-8"))
        if unfinished:
            failures.append(
                f"{unfinished} row(s) in analysis/_negatives.md have a blank Attack or Verdict cell, "
                "audit each cleared or refuted candidate or it is an unfinished negative, not a clear")

    # 5. No finding parked below HIGH; the bar is refuted or HIGH, never a MEDIUM discount.
    checked.append("no finding below HIGH")
    issues_dir = project_dir / "issues"
    if issues_dir.is_dir():
        for f in sorted(issues_dir.glob("*.md")):
            risk = _risk_value(f.read_text(encoding="utf-8"))
            if risk is None:
                failures.append(f"issues/{f.name} has no Risk line")
            elif "high" not in risk and "critical" not in risk:
                failures.append(
                    f"issues/{f.name} is graded '{risk}', below HIGH: refute it or grade it HIGH, "
                    "a precondition is not a severity discount")

    return GateResult(not failures, failures, checked)
