"""AdaptiveOrchestrator -- cheap triage, deep debate only where it pays off.

Most files are clean, and debate is several model calls; running it everywhere
wastes them. So this runs the single verifier first, then escalates to a full
Finder -> Challenger -> Judge debate only when the cheap pass found something
worth a second opinion:

- **high-risk**: any VULNERABLE verdict -- a flagged vulnerability is verified by
  the adversarial pass before it is reported / gates CI;
- **disputed**: a PARTIAL or UNKNOWN verdict the verifier is unsure about
  (confidence below the threshold).

A clean artifact (only confident SECURE / NOT_PRESENT verdicts) pays one verifier
call and stops. An escalated artifact is handed to the debate, whose deeper
ruling supersedes the triage verdicts for that artifact.
"""

from __future__ import annotations

from codejury.agents.base import Agent
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Verdict
from codejury.domain.result import AnalysisResult
from codejury.orchestrators.base import Orchestrator
from codejury.orchestrators.debate import DebateOrchestrator

_DISPUTABLE = ("PARTIAL", "UNKNOWN")


class AdaptiveOrchestrator(Orchestrator):
    def __init__(self, *, confidence_threshold: float = 0.7, debate: DebateOrchestrator | None = None) -> None:
        self._threshold = confidence_threshold
        self._debate = debate if debate is not None else DebateOrchestrator()

    def run(self, agents: dict[str, Agent], context: AnalysisContext) -> AnalysisResult:
        if "verifier" not in agents:
            return AnalysisResult(error="adaptive requires agents: verifier")
        try:
            verdicts = agents["verifier"].run(context)
        except Exception as exc:
            return AnalysisResult(error=f"agent 'verifier' failed: {exc}")

        if not self._needs_escalation(verdicts):
            return AnalysisResult(observations=verdicts)  # cheap path: confident, low-risk
        return self._debate.run(agents, context)          # deep path supersedes the triage

    def _needs_escalation(self, verdicts: list) -> bool:
        for v in verdicts:
            if not isinstance(v, Verdict):
                continue
            if v.status == "VULNERABLE":  # high-risk: verify a flagged vuln adversarially
                return True
            if v.status in _DISPUTABLE and v.confidence < self._threshold:  # disputed
                return True
        return False
