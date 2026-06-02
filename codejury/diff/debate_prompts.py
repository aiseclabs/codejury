"""Adversarial-mode prompts: three roles over the same diff.

- Finder (red team): attacker view, exhaustive, does not self-filter, so misses
  are rare.
- Challenger (blue team): two jobs in one pass: rebut each Finder finding it
  believes is a false positive, and independently scan the diff for what Finder
  missed.
- Judge: cross-validate both independent scans and rule each finding, keeping the
  survivors with calibrated severity.

The shared knowledge (focus areas, do-not-report list) is reused from the
standard prompt so the two modes hunt the same things.
"""

from __future__ import annotations

import json

from codejury.diff.prompts import DO_NOT_REPORT, FOCUS, category_block

_FINDING_FIELDS = (
    '{"file": "path", "line": 0, "severity": "CRITICAL|HIGH|MEDIUM|LOW", '
    '"category": "...", "description": "...", "exploit_scenario": "...", '
    '"recommendation": "...", "confidence": 0.0}'
)

FINDER_SYSTEM = (
    "You are a red-team application security engineer. Enumerate every plausible "
    "exploitable vulnerability an attacker could reach; do not self-censor or pre-filter "
    "for fear of false positives, the Challenger and Judge will do that. Respond with a "
    "single JSON object and nothing else."
)

CHALLENGER_SYSTEM = (
    "You are a blue-team security reviewer. You do two things: refute the reported "
    "findings you believe are false positives with concrete reasoning, and independently "
    "scan the same diff for real issues the finder missed. Respond with a single JSON "
    "object and nothing else."
)

JUDGE_SYSTEM = (
    "You are an impartial security judge. Weigh two independent reviews of the same diff "
    "and rule on each candidate finding, keeping only the ones the evidence supports, with "
    "calibrated severity. Respond with a single JSON object and nothing else."
)


def _diff_block(diff: str, rules: str, context: str) -> str:
    rules_block = f"Relevant security rules for reference:\n{rules}\n\n" if rules else ""
    context_block = f"Surrounding code (not under review):\n```\n{context}\n```\n\n" if context else ""
    return f"{rules_block}Code change (unified diff):\n```diff\n{diff}\n```\n\n{context_block}"


def finder_prompt(diff: str, *, rules: str = "", context: str = "", prior: list | None = None) -> str:
    prior_block = ""
    if prior:
        prior_block = (
            "Findings carried from the previous round (refine: drop any the rebuttals "
            "disprove, keep the valid ones, add anything still missed):\n"
            f"{json.dumps(prior, ensure_ascii=False)}\n\n"
        )
    return (
        "Find every exploitable vulnerability in this code change.\n\n"
        f"{FOCUS}\n{DO_NOT_REPORT}\n{category_block()}"
        f"{_diff_block(diff, rules, context)}{prior_block}"
        'Respond with a single JSON object exactly like: {"findings": [' + _FINDING_FIELDS + "]}"
    )


def challenger_prompt(diff: str, finder_findings: list, *, rules: str = "", context: str = "") -> str:
    return (
        "Two tasks on the code change below.\n"
        "1. For each reported finding you believe is a false positive, write a rebuttal "
        "with concrete reasoning (the value is not attacker-controlled, the sink is not "
        "reachable, a guard exists, etc.).\n"
        "2. Independently scan the diff yourself and report any real issue the finder missed.\n\n"
        f"{FOCUS}\n{DO_NOT_REPORT}\n{category_block()}"
        f"{_diff_block(diff, rules, context)}"
        f"Reported findings:\n{json.dumps(finder_findings, ensure_ascii=False)}\n\n"
        'Respond with a single JSON object exactly like: '
        '{"rebuttals": [{"target": "finding description or file:line", "verdict": "dismiss|downgrade", '
        '"reason": "..."}], "new_findings": [' + _FINDING_FIELDS + "]}"
    )


def judge_prompt(diff: str, finder_findings: list, rebuttals: list, new_findings: list, *, context: str = "") -> str:
    context_block = f"Surrounding code (not under review):\n```\n{context}\n```\n\n" if context else ""
    return (
        "Rule on each candidate finding from the two independent reviews below, assigning one verdict:\n"
        "- CONFIRMED: real and exploitable -> put it in `findings` at its severity.\n"
        "- DOWNGRADED: real but lower impact than claimed -> put it in `findings` at the lower severity, "
        "and record it in `downgraded`.\n"
        "- DISMISSED: a false positive the rebuttals disprove -> put it in `dismissed`.\n"
        "- UNRESOLVED: cannot decide from the code shown -> put it in `unresolved`.\n"
        "- INVESTIGATE: needs a dynamic/runtime check to confirm -> put it in `investigate`.\n"
        "Set `converged` to true when this round surfaced no new confirmed finding and nothing is left to "
        "investigate; false if another round could still change the ruling.\n\n"
        f"Code change (unified diff):\n```diff\n{diff}\n```\n\n{context_block}"
        f"Finder findings:\n{json.dumps(finder_findings, ensure_ascii=False)}\n\n"
        f"Challenger rebuttals:\n{json.dumps(rebuttals, ensure_ascii=False)}\n\n"
        f"Challenger independent findings:\n{json.dumps(new_findings, ensure_ascii=False)}\n\n"
        'Respond with a single JSON object exactly like: {"findings": [' + _FINDING_FIELDS + "], "
        '"downgraded": [{"target": "...", "from": "HIGH", "to": "MEDIUM", "reason": "..."}], '
        '"dismissed": [{"target": "...", "reason": "..."}], '
        '"unresolved": [{"target": "...", "reason": "..."}], '
        '"investigate": [{"target": "...", "reason": "..."}], '
        '"converged": true}'
    )
