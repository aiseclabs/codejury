"""ChallengeOrchestrator -- verify, then challenge the flagged verdicts.

The verifier rules on every capability; then a refuter is shown only the
VULNERABLE verdicts and the code, and argues which are false positives. A refuted
verdict becomes a dismissed Concession (recording why), so the report keeps the
SECURE/NOT_PRESENT verdicts, the surviving VULNERABLE ones, and a Dismissed list.

This targets taint-style false positives (which a lone verifier over-reports)
while paying the extra model call only for flagged verdicts, not the whole file.

Only verdicts from taint-prone capabilities are challenged. Local-pattern issues
(hardcoded secrets, weak crypto) are kept as-is: refuting them risks dropping a
real finding, and they do not have the attacker-control ambiguity that makes
taint checks over-report.
"""

from __future__ import annotations

import dataclasses

from codejury.agents.base import Agent
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Concession, Observation, Verdict
from codejury.domain.result import AnalysisResult
from codejury.orchestrators.base import Orchestrator

_REQUIRED_ROLES = ("verifier", "refuter")
_DEFAULT_TAINT_CAPABILITIES = frozenset({"input_validation"})


class ChallengeOrchestrator(Orchestrator):
    def __init__(self, *, taint_capabilities: frozenset[str] = _DEFAULT_TAINT_CAPABILITIES) -> None:
        self._taint_capabilities = taint_capabilities

    def run(self, agents: dict[str, Agent], context: AnalysisContext) -> AnalysisResult:
        missing = [role for role in _REQUIRED_ROLES if role not in agents]
        if missing:
            return AnalysisResult(error=f"challenge requires agents: {', '.join(missing)}")

        verdicts = agents["verifier"].run(context)
        flagged = [
            v
            for v in verdicts
            if isinstance(v, Verdict)
            and v.status == "VULNERABLE"
            and v.capability.split(".")[0] in self._taint_capabilities
        ]
        if not flagged:
            return AnalysisResult(observations=verdicts)

        refutations = agents["refuter"].run(dataclasses.replace(context, history=flagged))
        reasons = {c.target: c.reason for c in refutations if isinstance(c, Concession)}

        observations: list[Observation] = []
        for v in verdicts:
            if isinstance(v, Verdict) and v.status == "VULNERABLE" and v.capability in reasons:
                observations.append(
                    Concession(
                        capability=v.capability,
                        produced_by="refuter",
                        target=v.capability,
                        reason=reasons[v.capability] or "refuted as a false positive",
                    )
                )
            else:
                observations.append(v)
        return AnalysisResult(observations=observations)
