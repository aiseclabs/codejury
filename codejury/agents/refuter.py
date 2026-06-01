"""RefuterAgent -- a skeptic that tries to dismiss flagged verdicts as false positives.

Used by the challenge orchestrator: the verifier flags issues, then the refuter
gets the code plus the VULNERABLE verdicts (via ``ctx.history``) and argues which
are false positives -- e.g. a value that is not actually attacker-controlled or a
sink that is not reachable. It returns a Concession per verdict it refutes.

This is the cheap, focused alternative to a full debate: only flagged verdicts
are challenged, not the whole file.
"""

from __future__ import annotations

from codejury.agents.base import Agent
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Concession, Observation, Verdict
from codejury.infrastructure.json_parse import extract_json_object
from codejury.providers.base import Message, Provider

_SYSTEM = (
    "You are a careful security reviewer checking flagged issues for false positives. "
    "Security errs toward keeping a flag: refute one ONLY when the code in front of you "
    "affirmatively proves the value is not attacker-controlled. If a value's origin is not "
    "shown, or it could plausibly come from external/untrusted input, KEEP the flag. "
    "Respond with a single JSON object and nothing else."
)

_JSON_SHAPE = '{"refuted": [{"capability": "id.sub", "reason": "proof it is not attacker-controlled"}]}'


class RefuterAgent(Agent):
    def __init__(self, *, provider: Provider, model: str, max_tokens: int = 1024) -> None:
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens

    def run(self, ctx: AnalysisContext) -> list[Observation]:
        flagged = [o for o in ctx.history if isinstance(o, Verdict)]
        if not flagged:
            return []
        flags = "\n".join(f"- {v.capability}: {v.reasoning}" for v in flagged)
        context_block = (
            f"Call sites elsewhere (for tracing where arguments come from):\n```\n{ctx.artifact.context}\n```\n\n"
            if ctx.artifact.context
            else ""
        )
        prompt = (
            f"Code under review ({ctx.artifact.path}):\n```\n{ctx.artifact.content}\n```\n\n"
            f"{context_block}"
            f"Flagged issues:\n{flags}\n\n"
            "This attacker-control reasoning applies ONLY to input-driven issues (injection, path "
            "traversal, SSRF). For those, refute a flag only if you can affirmatively prove the value "
            "is not attacker-controlled: a stored data field, or traced (here or in the call sites) to "
            "a trusted, config, or operator-supplied source. If its origin is not shown or could "
            "plausibly be external input, do NOT refute. For other issue types (hardcoded secrets, "
            "weak crypto, ...), a literal value is often the vulnerability itself -- do NOT refute "
            "those just because a value is constant.\n\n"
            "Respond with a single JSON object exactly like:\n" + _JSON_SHAPE
        )
        result = self._provider.complete(
            system=_SYSTEM,
            messages=[Message(role="user", content=prompt)],
            model=self._model,
            max_tokens=self._max_tokens,
        )
        obj = extract_json_object(result.text) or {}
        out: list[Observation] = []
        for item in obj.get("refuted", []):
            if not isinstance(item, dict):
                continue
            capability = str(item.get("capability", "")).strip()
            if capability:
                out.append(
                    Concession(capability=capability, produced_by="refuter", target=capability, reason=str(item.get("reason", "")))
                )
        return out
