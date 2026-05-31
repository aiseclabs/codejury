"""VerifierAgent -- check code against a capability's correct/anti patterns.

It renders the capability into a prompt, calls the provider once per capability,
and parses the JSON reply into Verdicts. It asks for one verdict per
sub_capability including SECURE / NOT_PRESENT, so a report can say what was
checked and what passed -- not only what failed.

Parsing is defensive: a missing or malformed reply yields no verdicts rather
than raising, and unknown status values fall back to UNKNOWN.
"""

from __future__ import annotations

from codejury.agents.base import Agent
from codejury.domain.capability import Capability
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Evidence, Observation, Verdict
from codejury.infrastructure.json_parse import extract_json_object
from codejury.providers.base import Message, Provider

_VALID_STATUS = {"SECURE", "VULNERABLE", "PARTIAL", "NOT_PRESENT", "UNKNOWN"}

_SYSTEM = (
    "You are a security verifier. You check code against a checklist of correct and "
    "anti patterns and rule on each dimension, reporting what is fine as well as what "
    "is wrong. Respond with a single JSON object and nothing else."
)

_JSON_SHAPE = (
    '{"verdicts": [{"sub_capability": "...", '
    '"status": "SECURE|VULNERABLE|PARTIAL|NOT_PRESENT|UNKNOWN", "reasoning": "...", '
    '"matched_correct": ["id"], "matched_anti": ["id"], '
    '"evidence": [{"file": "path", "line": 0, "code": "..."}], "confidence": 0.0}]}'
)


class VerifierAgent(Agent):
    def __init__(self, *, provider: Provider, model: str, max_tokens: int = 2048) -> None:
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens

    def run(self, ctx: AnalysisContext) -> list[Observation]:
        verdicts: list[Observation] = []
        for cap in ctx.capabilities:
            prompt = _build_prompt(ctx.artifact.path, ctx.artifact.content, cap)
            result = self._provider.complete(
                system=_SYSTEM,
                messages=[Message(role="user", content=prompt)],
                model=self._model,
                max_tokens=self._max_tokens,
            )
            verdicts.extend(_parse_verdicts(result.text, cap))
        return verdicts


def _render_capability(cap: Capability) -> str:
    lines = [f"Capability: {cap.id} ({cap.name})"]
    for sub_name, sub in cap.sub_capabilities.items():
        lines.append(f"\nsub_capability: {sub_name}")
        if sub.correct_patterns:
            lines.append("  correct patterns:")
            lines += [f"    - {p.id}: {p.description}" for p in sub.correct_patterns]
        if sub.anti_patterns:
            lines.append("  anti patterns:")
            for p in sub.anti_patterns:
                tag = f"[{p.cwe} {p.severity}]" if p.cwe else f"[{p.severity}]"
                lines.append(f"    - {p.id} {tag}: {p.description}")
    return "\n".join(lines)


def _build_prompt(path: str, content: str, cap: Capability) -> str:
    sub_names = ", ".join(cap.sub_capabilities) or "(none)"
    return (
        "Check the code below against this capability.\n\n"
        f"{_render_capability(cap)}\n\n"
        f"Code under review ({path}):\n```\n{content}\n```\n\n"
        f"For EVERY sub_capability ({sub_names}) output one verdict, even if SECURE "
        "or NOT_PRESENT. Cite matched pattern ids and evidence lines.\n\n"
        "Respond with a single JSON object exactly like:\n" + _JSON_SHAPE
    )


def _parse_verdicts(text: str, cap: Capability) -> list[Verdict]:
    obj = extract_json_object(text)
    if not obj:
        return []
    out: list[Verdict] = []
    for v in obj.get("verdicts", []):
        if not isinstance(v, dict):
            continue
        sub = str(v.get("sub_capability", "")).strip()
        status = v.get("status", "UNKNOWN")
        out.append(
            Verdict(
                capability=f"{cap.id}.{sub}" if sub else cap.id,
                produced_by="verifier",
                status=status if status in _VALID_STATUS else "UNKNOWN",
                reasoning=str(v.get("reasoning", "")),
                matched_correct=_str_list(v.get("matched_correct")),
                matched_anti=_str_list(v.get("matched_anti")),
                evidence=_parse_evidence(v.get("evidence")),
                confidence=_as_float(v.get("confidence"), 0.5),
            )
        )
    return out


def _parse_evidence(items: object) -> list[Evidence]:
    if not isinstance(items, list):
        return []
    out: list[Evidence] = []
    for e in items:
        if not isinstance(e, dict):
            continue
        line = e.get("line")
        out.append(
            Evidence(
                file=str(e.get("file", "")),
                line=line if isinstance(line, int) else None,
                code=str(e.get("code", "")),
                note=str(e.get("note", "")),
            )
        )
    return out


def _str_list(value: object) -> list[str]:
    return [str(x) for x in value] if isinstance(value, list) else []


def _as_float(value: object, default: float) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
