"""Render audit results into machine- and human-readable reports.

Input is the per-file ``[(path, AnalysisResult)]`` the audit produces. JSON is
for tooling; Markdown is for a human reviewer and leads with the issues, then
shows what was checked and cleared (the "why it's fine" side) and what was
dismissed.
"""

from __future__ import annotations

import json

from codejury.domain.observation import Observation
from codejury.domain.result import AnalysisResult

Results = list[tuple[str, AnalysisResult]]

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_CLEARED = ("SECURE", "NOT_PRESENT")
_PROBLEM_STATUSES = ("VULNERABLE", "PARTIAL")


def to_json(results: Results) -> str:
    payload = {
        "files": [
            {
                "path": path,
                "error": result.error,
                "observations": [o.to_dict() for o in result.observations],
            }
            for path, result in results
        ]
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def to_markdown(results: Results) -> str:
    lines = ["# Security Audit Report", ""]
    lines += _summary(results)
    for path, result in results:
        lines += ["", f"## {path}"]
        if result.error:
            lines.append(f"> error: {result.error}")

        problems = sorted((o for o in result.observations if _is_problem(o)), key=_rank)
        cleared = [o for o in result.observations if o.kind == "verdict" and o.status in _CLEARED]
        dismissed = [o for o in result.observations if o.kind == "concession"]

        if problems:
            lines += ["", "### Issues"]
            for o in problems:
                lines += _render_problem(o)
        if cleared:
            lines += ["", "### Checked and clear"]
            lines += [f"- {o.status} `{o.capability}`" for o in cleared]
        if dismissed:
            lines += ["", "### Dismissed"]
            lines += [f"- ~~{o.target}~~ — {o.reason}" for o in dismissed]
        if not result.observations and not result.error:
            lines += ["", "_no observations_"]
    return "\n".join(lines)


def _summary(results: Results) -> list[str]:
    vulnerable = cleared = findings = dismissed = 0
    for _, result in results:
        for o in result.observations:
            if o.kind == "verdict":
                vulnerable += o.status in _PROBLEM_STATUSES
                cleared += o.status in _CLEARED
            elif o.kind == "finding":
                findings += 1
            elif o.kind == "concession":
                dismissed += 1
    return [
        f"- files audited: {len(results)}",
        f"- issues: {vulnerable} vulnerable verdict(s), {findings} finding(s)",
        f"- checked and clear: {cleared}",
        f"- dismissed: {dismissed}",
    ]


def _is_problem(o: Observation) -> bool:
    return o.kind == "finding" or (o.kind == "verdict" and o.status in _PROBLEM_STATUSES)


def _rank(o: Observation) -> int:
    if o.kind == "finding":
        return _SEVERITY_ORDER.get(o.severity, 5)
    return -1 if o.status == "VULNERABLE" else 4  # vulnerable verdicts float to the top


def _render_problem(o: Observation) -> list[str]:
    if o.kind == "finding":
        cwe = f" ({o.cwe})" if o.cwe else ""
        out = [f"- **{o.severity}**{cwe} {o.title}"]
        if o.description:
            out.append(f"  - {o.description}")
    else:
        matched = ", ".join(o.matched_anti)
        tag = f" [{matched}]" if matched else ""
        out = [f"- **{o.status}** `{o.capability}`{tag}"]
        if o.reasoning:
            out.append(f"  - {o.reasoning}")
    return out + _evidence_lines(o.evidence)


def _evidence_lines(evidence) -> list[str]:
    lines = []
    for e in evidence:
        location = e.file + (f":{e.line}" if e.line else "")
        code = f" `{e.code}`" if e.code else ""
        lines.append(f"  - {location}{code}")
    return lines
