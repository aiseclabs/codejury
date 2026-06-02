"""SkillRunner: execute a skill's playbook against a piece of code.

The agent that rules code against a skill. It hands the model the skill's
SKILL.md playbook verbatim and asks it to rule on each dimension the playbook
names. One provider call per skill.

Parsing is defensive: a missing or malformed reply yields no verdicts rather
than raising, and unknown status values fall back to UNKNOWN. Invariant 3 is
enforced here: a problem verdict (VULNERABLE / PARTIAL) with no code location is
not reportable, so it is dropped.
"""

from __future__ import annotations

from typing import get_args

from codejury.agents.base import Agent
from codejury.agents.parsing import one_of, to_evidence, to_float
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Observation, Verdict, VerdictStatus
from codejury.domain.skill import Skill
from codejury.infrastructure.json_parse import extract_json_object
from codejury.providers.base import Message, Provider

_VALID_STATUS = set(get_args(VerdictStatus))
_PROBLEM = {"VULNERABLE", "PARTIAL"}  # statuses that require a code location

_SYSTEM = (
    "You are a security reviewer executing one specific check skill. Follow the "
    "skill's playbook exactly, ruling on what is fine as well as what is wrong. "
    "Respond with a single JSON object and nothing else."
)

_JSON_SHAPE = (
    '{"verdicts": [{"dimension": "...", '
    '"status": "SECURE|VULNERABLE|PARTIAL|NOT_PRESENT|UNKNOWN", "reasoning": "...", '
    '"evidence": [{"file": "path", "line": 0, "code": "..."}], '
    '"cwe": "CWE-...", "confidence": 0.0}]}'
)


class SkillRunner(Agent):
    def __init__(self, *, provider: Provider, model: str, max_tokens: int = 2048) -> None:
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens

    def run(self, ctx: AnalysisContext) -> list[Observation]:
        out: list[Observation] = []
        for skill in ctx.skills:
            prompt = _build_prompt(ctx.artifact.path, ctx.artifact.content, skill, ctx.artifact.context)
            result = self._provider.complete(
                system=_SYSTEM,
                messages=[Message(role="user", content=prompt)],
                model=self._model,
                max_tokens=self._max_tokens,
            )
            out.extend(_parse_verdicts(result.text, skill))
        return out


def _render_skill(skill: Skill) -> str:
    header = f"Skill: {skill.id} ({skill.name})"
    if skill.standard:
        header += f"\nStandard: {skill.standard}"
    return f"{header}\n\n{skill.instructions}"


def _build_prompt(path: str, content: str, skill: Skill, context: str = "") -> str:
    context_block = (
        f"Related code (call sites / usages elsewhere, for tracing where values come from, "
        f"NOT under review):\n```\n{context}\n```\n\n"
        if context
        else ""
    )
    return (
        "Apply the security check skill below to the code.\n\n"
        f"{_render_skill(skill)}\n\n"
        f"Code under review ({path}):\n```\n{content}\n```\n\n"
        f"{context_block}"
        "Output one verdict per dimension the skill covers, even when SECURE or "
        "NOT_PRESENT, so the report says what was checked and what passed. Cite an "
        "evidence file and line for every VULNERABLE or PARTIAL verdict.\n"
        "For input-driven issues (injection, path traversal, SSRF), mark VULNERABLE only when "
        "untrusted/external input could plausibly reach the sink in the code shown. A constant, "
        "a stored data field, a value from trusted config, or a path or argument the operator "
        "supplies (e.g. a CLI argument) is not attacker-controlled; do not flag it.\n\n"
        "Respond with a single JSON object exactly like:\n" + _JSON_SHAPE
    )


def _has_location(evidence: list) -> bool:
    return any(e.line is not None for e in evidence)


def _parse_verdicts(text: str, skill: Skill) -> list[Verdict]:
    obj = extract_json_object(text)
    if not obj:
        return []
    out: list[Verdict] = []
    for v in obj.get("verdicts", []):
        if not isinstance(v, dict):
            continue
        status = one_of(v.get("status"), _VALID_STATUS, "UNKNOWN")
        evidence = to_evidence(v.get("evidence"))
        if status in _PROBLEM and not _has_location(evidence):
            continue  # invariant 3: a problem with no code location is not reportable
        dimension = str(v.get("dimension", "")).strip()
        cwe = str(v.get("cwe", "")).strip() or skill.cwe
        out.append(
            Verdict(
                capability=f"{skill.id}.{dimension}" if dimension else skill.id,
                produced_by="skill",
                status=status,
                reasoning=str(v.get("reasoning", "")),
                cwe=cwe,
                evidence=evidence,
                confidence=to_float(v.get("confidence"), 0.5),
            )
        )
    return out
