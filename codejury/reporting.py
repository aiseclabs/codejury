"""Render audit results into machine- and human-readable reports.

Input is the per-file ``[(path, AnalysisResult)]`` the audit produces. JSON is
for tooling; Markdown is for a human reviewer and leads with the issues, then
shows what was checked and cleared (the "why it's fine" side) and what was
dismissed.
"""

from __future__ import annotations

import json

from codejury import __version__ as _tool_version
from codejury.domain.observation import Observation, is_problem, observation_from_dict
from codejury.domain.result import AnalysisResult

Results = list[tuple[str, AnalysisResult]]

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_CLEARED = ("SECURE", "NOT_PRESENT")
_PROBLEM_STATUSES = ("VULNERABLE", "PARTIAL")

# Finding severity -> SARIF result level; VULNERABLE verdict is error, PARTIAL warning.
_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}


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


def from_json(text: str) -> Results:
    """Parse a ``to_json`` report back into results (used to load a diff baseline).

    Raises ValueError on a malformed report (it is external, possibly hand-edited,
    input) rather than an opaque KeyError/TypeError.
    """
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"baseline report is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("baseline report must be a JSON object with a 'files' list")
    return [
        (
            f.get("path", ""),
            AnalysisResult(
                observations=[observation_from_dict(o) for o in f.get("observations", [])],
                error=f.get("error"),
            ),
        )
        for f in payload.get("files", [])
    ]


def to_markdown(results: Results) -> str:
    lines = ["# Security Audit Report", ""]
    lines += _summary(results)
    for path, result in results:
        lines += ["", f"## {path}"]
        if result.error:
            lines.append(f"> error: {result.error}")

        problems = sorted((o for o in result.observations if is_problem(o)), key=_rank)
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
        f"- issues: {vulnerable} problem verdict(s) (VULNERABLE/PARTIAL), {findings} finding(s)",
        f"- checked and clear: {cleared}",
        f"- dismissed: {dismissed}",
    ]


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


def to_sarif(results: Results) -> str:
    """Render problems as a SARIF 2.1.0 log for CI and security dashboards.

    Only problems with a code location are emitted (invariant 3: no location ->
    not reportable). Each result carries its capability (as ``ruleId``), the CWE,
    and a precise physical location.
    """
    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    sarif_results = []

    for _, result in results:
        for o in result.observations:
            if not is_problem(o):
                continue
            locations = _sarif_locations(o)
            if not locations:
                continue
            rule_id = o.capability or "codejury"
            cwe = getattr(o, "cwe", "")
            if rule_id not in rule_index:
                rule_index[rule_id] = len(rules)
                rules.append(_sarif_rule(rule_id, cwe))
            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "ruleIndex": rule_index[rule_id],
                    "level": _sarif_level(o),
                    "message": {"text": _sarif_message(o)},
                    "locations": locations,
                    "properties": {"capability": o.capability, "cwe": cwe, "confidence": o.confidence},
                }
            )

    log = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "codejury",
                        "informationUri": "https://github.com/aiseclabs/codejury",
                        "version": _tool_version,
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(log, indent=2, ensure_ascii=False)


def _sarif_rule(rule_id: str, cwe: str) -> dict:
    rule = {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": f"codejury capability: {rule_id}"},
        "properties": {"tags": ["security"] + ([cwe] if cwe else [])},
    }
    if cwe:
        rule["properties"]["cwe"] = cwe
    return rule


def _sarif_level(o: Observation) -> str:
    if o.kind == "finding":
        return _SARIF_LEVEL.get(o.severity, "warning")
    return "error" if o.status == "VULNERABLE" else "warning"  # PARTIAL


def _sarif_message(o: Observation) -> str:
    if o.kind == "finding":
        return o.title + (f" -- {o.description}" if o.description else "")
    return f"{o.status} {o.capability}" + (f" -- {o.reasoning}" if o.reasoning else "")


def _sarif_locations(o: Observation) -> list[dict]:
    locations = []
    for e in getattr(o, "evidence", []):
        if not e.file:  # invariant 3: a location needs at least a file
            continue
        physical: dict = {"artifactLocation": {"uri": e.file}}
        if e.line:
            region: dict = {"startLine": e.line}
            if e.end_line:
                region["endLine"] = e.end_line
            if e.code:
                region["snippet"] = {"text": e.code}
            physical["region"] = region
        locations.append({"physicalLocation": physical})
    return locations
