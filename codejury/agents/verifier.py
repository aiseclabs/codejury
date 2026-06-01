"""VerifierAgent: check code against a capability's correct/anti patterns.

It renders the capability into a prompt, calls the provider once per capability,
and parses the JSON reply into Verdicts. It asks for one verdict per
sub_capability including SECURE / NOT_PRESENT, so a report can say what was
checked and what passed, not only what failed.

Parsing is defensive: a missing or malformed reply yields no verdicts rather
than raising, and unknown status values fall back to UNKNOWN.
"""

from __future__ import annotations

from codejury.agents.base import Agent
from codejury.agents.parsing import one_of, str_list, to_evidence, to_float
from codejury.domain.capability import Capability
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Observation, Verdict, VerdictStatus
from codejury.infrastructure.json_parse import extract_json_object
from codejury.providers.base import Message, Provider

from typing import get_args

_VALID_STATUS = set(get_args(VerdictStatus))  # single source of truth: the VerdictStatus Literal

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
            prompt = _build_prompt(ctx.artifact.path, ctx.artifact.content, cap, ctx.artifact.context)
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


def _build_prompt(path: str, content: str, cap: Capability, context: str = "") -> str:
    sub_names = ", ".join(cap.sub_capabilities) or "(none)"
    context_block = (
        f"Related code (call sites / usages elsewhere, for tracing where values come from, "
        f"NOT under review):\n```\n{context}\n```\n\n"
        if context
        else ""
    )
    return (
        "Check the code below against this capability.\n\n"
        f"{_render_capability(cap)}\n\n"
        f"Code under review ({path}):\n```\n{content}\n```\n\n"
        f"{context_block}"
        f"For EVERY sub_capability ({sub_names}) output one verdict, even if SECURE "
        "or NOT_PRESENT. Cite matched pattern ids and evidence lines.\n"
        "For input-driven issues (injection, path traversal, SSRF), mark VULNERABLE only when "
        "untrusted/external input could plausibly reach the sink in the code shown. A constant, "
        "a stored data field, a value from trusted config, or a path or argument the operator "
        "supplies (e.g. a CLI argument) is not attacker-controlled; do not flag it.\n\n"
        "Respond with a single JSON object exactly like:\n" + _JSON_SHAPE
    )


_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _anti_pattern_cwes(cap: Capability) -> dict[str, tuple[int, str]]:
    """Map anti_pattern id -> (severity rank, CWE), so a verdict can inherit the CWE
    of the most severe anti-pattern it matched (deterministic, not first-seen)."""
    return {
        p.id: (_SEVERITY_RANK.get(p.severity, 2), p.cwe)
        for sub in cap.sub_capabilities.values()
        for p in sub.anti_patterns
        if p.cwe
    }


def _resolve_cwe(matched_anti: list[str], cwe_by_id: dict[str, tuple[int, str]]) -> str:
    # the most severe matched anti-pattern's CWE; ties broken by CWE id so the result
    # is fully determined by the inputs, not by dict/list ordering.
    matched = [cwe_by_id[a] for a in matched_anti if a in cwe_by_id]
    return max(matched, key=lambda rank_cwe: (rank_cwe[0], rank_cwe[1]))[1] if matched else ""


def _parse_verdicts(text: str, cap: Capability) -> list[Verdict]:
    obj = extract_json_object(text)
    if not obj:
        return []
    cwe_by_id = _anti_pattern_cwes(cap)
    out: list[Verdict] = []
    for v in obj.get("verdicts", []):
        if not isinstance(v, dict):
            continue
        sub = str(v.get("sub_capability", "")).strip()
        matched_anti = str_list(v.get("matched_anti"))
        out.append(
            Verdict(
                capability=f"{cap.id}.{sub}" if sub else cap.id,
                produced_by="verifier",
                status=one_of(v.get("status"), _VALID_STATUS, "UNKNOWN"),
                reasoning=str(v.get("reasoning", "")),
                matched_correct=str_list(v.get("matched_correct")),
                matched_anti=matched_anti,
                cwe=_resolve_cwe(matched_anti, cwe_by_id),
                evidence=to_evidence(v.get("evidence")),
                confidence=to_float(v.get("confidence"), 0.5),
            )
        )
    return out
