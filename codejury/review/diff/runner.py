"""Diff-audit orchestration: run a diff through the engine and clean the result.

The library entry point behind `review diff`. Picks the standard or adversarial
engine, audits a large diff one file at a time so a big PR does not overflow the
model context, normalizes finding categories onto the rule-id set, and applies
the false-positive filter. Kept out of the CLI so it can be called as a library.
"""

from __future__ import annotations

import dataclasses

from codejury.review.diff.debate import AdversarialAuditRunner
from codejury.review.diff.engine import AuditRunner
from codejury.review.diff.findings_filter import FindingsFilter
from codejury.review.diff.vulnerabilities import allowed_categories, normalize_category
from codejury.domain.finding import Finding

# A diff larger than this is audited file-by-file so a big PR does not overflow
# the model's context and silently truncate the reply.
_MAX_DIFF_CHARS = 60_000


def split_diff_by_file(diff: str) -> list[str]:
    """Split a unified diff into one diff per file (`diff --git ...` boundaries)."""
    chunks: list[str] = []
    cur: list[str] = []
    for line in diff.splitlines(keepends=True):
        if line.startswith("diff --git ") and cur:
            chunks.append("".join(cur))
            cur = []
        cur.append(line)
    if cur:
        chunks.append("".join(cur))
    return chunks or ([diff] if diff.strip() else [])


def dedup_findings(findings: list[Finding]) -> list[Finding]:
    seen: set = set()
    out: list[Finding] = []
    for f in findings:
        k = (f.file, f.line, f.category, f.description)
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def audit_diff(
    diff: str,
    *,
    provider,
    model: str,
    mode: str = "standard",
    max_rounds: int = 3,
    filter_findings: bool = True,
    finder_model: str | None = None,
    challenger_model: str | None = None,
    judge_model: str | None = None,
    exclude_paths: tuple[str, ...] = (),
) -> tuple[list[Finding], list[tuple[Finding, str]]]:
    """Audit a diff and return (kept findings, dropped (finding, reason)).

    A diff over the size budget is audited one file at a time so it does not
    overflow the context. Finding categories are normalized to the rule-id set.
    ``exclude_paths`` are operator-supplied path substrings to drop."""
    def _run_one(d: str) -> list[Finding]:
        if mode == "adversarial":
            return AdversarialAuditRunner(
                provider=provider, model=model,
                finder_model=finder_model, challenger_model=challenger_model, judge_model=judge_model,
            ).run(d, max_rounds=max_rounds).findings
        return AuditRunner(provider=provider, model=model).run(d)

    if len(diff) > _MAX_DIFF_CHARS:
        chunks = split_diff_by_file(diff)
        findings = dedup_findings([f for c in chunks for f in _run_one(c)])
    else:
        findings = _run_one(diff)

    allowed = set(allowed_categories())
    findings = [dataclasses.replace(f, category=normalize_category(f.category, allowed)) for f in findings]
    if filter_findings:
        return FindingsFilter(exclude_paths=exclude_paths).filter(findings)
    return findings, []
