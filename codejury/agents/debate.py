"""Finder / Challenger / Judge agents for the debate orchestrator.

Each reads the artifact, the capability hints, and the accumulated history
(prior findings and rebuttals) from the context, calls the provider once, and
maps its JSON reply onto observations:

- Finder    -> Finding (claims) + Concession (its own retractions)
- Challenger -> Concession (moves to dismiss findings) + Finding (ones it missed)
- Judge     -> Finding (surviving) + Concession (dismissed)

The orchestrator threads history and round_num across rounds; convergence is the
orchestrator's job, not encoded here.
"""

from __future__ import annotations

from codejury.agents.base import Agent
from codejury.agents.parsing import one_of, str_list, to_evidence, to_float
from codejury.domain.artifact import CodeArtifact
from codejury.domain.capability import Capability
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Concession, Finding, Observation
from codejury.infrastructure.json_parse import extract_json_object
from codejury.providers.base import Message, Provider

_SEVERITY = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

_FINDING_SHAPE = (
    '{"capability": "id.sub", "title": "...", "severity": "HIGH", "cwe": "CWE-89", '
    '"description": "...", "evidence": [{"file": "...", "line": 0, "code": "..."}], "confidence": 0.0}'
)


class _DebateAgent(Agent):
    """Shared provider plumbing for the three debate roles."""

    role = "agent"
    system = ""

    def __init__(self, *, provider: Provider, model: str, max_tokens: int = 2048) -> None:
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens

    def _ask(self, prompt: str) -> dict:
        result = self._provider.complete(
            system=self.system,
            messages=[Message(role="user", content=prompt)],
            model=self._model,
            max_tokens=self._max_tokens,
        )
        return extract_json_object(result.text) or {}


class FinderAgent(_DebateAgent):
    role = "finder"
    system = (
        "You are a security finder. Identify real, exploitable vulnerabilities in the code, "
        "being precise and avoiding false positives. Respond with a single JSON object and nothing else."
    )

    def run(self, ctx: AnalysisContext) -> list[Observation]:
        parts = ["Review the code for security vulnerabilities.", _hints(ctx.capabilities), _code(ctx.artifact)]
        if ctx.round_num > 1 and ctx.history:
            parts.append(_render_history(ctx.history))
            parts.append("Concede findings the rebuttals refute, keep the valid ones, and add any you missed.")
        parts.append(
            'Respond as JSON: {"findings": [' + _FINDING_SHAPE + '], '
            '"concessions": [{"target": "finding title", "reason": "..."}]}'
        )
        obj = self._ask("\n\n".join(p for p in parts if p))
        return _findings(obj.get("findings"), self.role, ctx.round_num) + _concessions(
            obj.get("concessions"), self.role, ctx.round_num
        )


class ChallengerAgent(_DebateAgent):
    role = "challenger"
    system = (
        "You are a skeptical security reviewer. Challenge each reported finding and try to refute it "
        "with concrete reasoning. Respond with a single JSON object and nothing else."
    )

    def run(self, ctx: AnalysisContext) -> list[Observation]:
        parts = [
            "Challenge the findings below. For each one you believe is a false positive, write a rebuttal. "
            "Add new_findings for any real issue that was missed.",
            _code(ctx.artifact),
            _render_history(ctx.history),
            'Respond as JSON: {"rebuttals": [{"target": "finding title", "reason": "..."}], '
            '"new_findings": [' + _FINDING_SHAPE + "]}",
        ]
        obj = self._ask("\n\n".join(p for p in parts if p))
        return _concessions(obj.get("rebuttals"), self.role, ctx.round_num) + _findings(
            obj.get("new_findings"), self.role, ctx.round_num
        )


class JudgeAgent(_DebateAgent):
    role = "judge"
    system = (
        "You are an impartial security judge. Weighing the findings and rebuttals, decide which findings "
        "survive scrutiny and which are dismissed. Respond with a single JSON object and nothing else."
    )

    def run(self, ctx: AnalysisContext) -> list[Observation]:
        parts = [
            "Rule on the debate below. Keep findings that withstand the rebuttals; dismiss the rest.",
            _code(ctx.artifact),
            _render_history(ctx.history),
            'Respond as JSON: {"surviving": [' + _FINDING_SHAPE + '], '
            '"dismissed": [{"target": "finding title", "reason": "..."}]}',
        ]
        obj = self._ask("\n\n".join(p for p in parts if p))
        return _findings(obj.get("surviving"), self.role, ctx.round_num) + _concessions(
            obj.get("dismissed"), self.role, ctx.round_num
        )


def _code(artifact: CodeArtifact) -> str:
    return f"Code under review ({artifact.path}):\n```\n{artifact.content}\n```"


def _hints(capabilities: list[Capability]) -> str:
    lines = []
    for cap in capabilities:
        for sub_name, sub in cap.sub_capabilities.items():
            for ap in sub.anti_patterns:
                tag = f"{ap.cwe} {ap.severity}" if ap.cwe else ap.severity
                lines.append(f"- {cap.id}.{sub_name} [{tag}]: {ap.description}")
    return "Look especially for:\n" + "\n".join(lines) if lines else ""


def _render_history(history: list[Observation]) -> str:
    findings = [o for o in history if isinstance(o, Finding)]
    concessions = [o for o in history if isinstance(o, Concession)]
    blocks = []
    if findings:
        lines = [
            f'- [{f.produced_by} r{f.round_num}] "{f.title}" ({f.severity}{", " + f.cwe if f.cwe else ""}): '
            f"{f.description}"
            for f in findings
        ]
        blocks.append("Findings so far:\n" + "\n".join(lines))
    if concessions:
        lines = [f'- [{c.produced_by} r{c.round_num}] dismiss "{c.target}": {c.reason}' for c in concessions]
        blocks.append("Rebuttals / concessions so far:\n" + "\n".join(lines))
    return "\n\n".join(blocks)


def _findings(items: object, produced_by: str, round_num: int) -> list[Finding]:
    out: list[Finding] = []
    for f in _dicts(items):
        title = str(f.get("title", "")).strip()
        if not title:
            continue
        out.append(
            Finding(
                produced_by=produced_by,
                round_num=round_num,
                capability=str(f.get("capability", "")),
                title=title,
                description=str(f.get("description", "")),
                severity=one_of(f.get("severity"), _SEVERITY, "MEDIUM"),
                cwe=str(f.get("cwe", "")),
                evidence=to_evidence(f.get("evidence")),
                recommendation=str(f.get("recommendation", "")),
                matched_anti=str_list(f.get("matched_anti")),
                confidence=to_float(f.get("confidence"), 0.5),
            )
        )
    return out


def _concessions(items: object, produced_by: str, round_num: int) -> list[Concession]:
    out: list[Concession] = []
    for c in _dicts(items):
        target = str(c.get("target", "")).strip()
        if not target:
            continue
        out.append(
            Concession(produced_by=produced_by, round_num=round_num, target=target, reason=str(c.get("reason", "")))
        )
    return out


def _dicts(items: object) -> list[dict]:
    return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []
