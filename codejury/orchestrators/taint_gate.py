"""TaintGateOrchestrator -- verify, then clear taint findings that data-flow proves safe.

The verifier rules on every capability; then, for taint-prone capabilities
(input_validation), the provenance engine checks whether any attacker-controlled,
unsanitized value actually reaches a sink in the artifact -- using the
caller/callee code in ``artifact.context`` for the cross-file hop. If the whole
artifact is provably clean (every sink receives a constant, sanitized, or trusted
value), the flagged VULNERABLE verdicts are dismissed as Concessions citing the
provenance.

This is the conservative half of P1: it downgrades only on positive proof of
safety. Anything uncertain (an unknown call, an unresolved parameter, code that
does not parse) keeps the verdict, so recall is preserved -- the gate trades only
false positives, never a real finding. Unlike the refuter in ``challenge``, the
decision is static analysis, not an LLM opinion.
"""

from __future__ import annotations

from codejury.agents.base import Agent
from codejury.analysis.taint import SAFE, TaintVocab, load_vocab, worst_sink_taint
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Concession, Observation, Verdict
from codejury.domain.result import AnalysisResult
from codejury.orchestrators.base import Orchestrator

_DEFAULT_TAINT_CAPABILITIES = frozenset({"input_validation"})


class TaintGateOrchestrator(Orchestrator):
    def __init__(
        self,
        *,
        vocab: TaintVocab | None = None,
        taint_capabilities: frozenset[str] = _DEFAULT_TAINT_CAPABILITIES,
    ) -> None:
        self._vocab = vocab if vocab is not None else load_vocab()
        self._taint_capabilities = taint_capabilities

    def run(self, agents: dict[str, Agent], context: AnalysisContext) -> AnalysisResult:
        if "verifier" not in agents:
            return AnalysisResult(error="taint requires agents: verifier")
        try:
            verdicts = agents["verifier"].run(context)
        except Exception as exc:
            return AnalysisResult(error=f"agent 'verifier' failed: {exc}")

        artifact = context.artifact
        files = {artifact.path or "<artifact>": artifact.content}
        if artifact.context:
            files["<context>"] = artifact.context

        worst = worst_sink_taint(artifact.content, files, self._vocab)
        if worst is None or worst not in SAFE:
            return AnalysisResult(observations=verdicts)  # cannot prove safe -> keep everything

        observations: list[Observation] = []
        for v in verdicts:
            if (
                isinstance(v, Verdict)
                and v.status in ("VULNERABLE", "PARTIAL")
                and v.capability.split(".")[0] in self._taint_capabilities
            ):
                observations.append(
                    Concession(
                        capability=v.capability,
                        produced_by="provenance",
                        target=v.capability,
                        reason=f"provenance: the value reaching the sink is {worst.value}, "
                        "not attacker-controlled",
                    )
                )
            else:
                observations.append(v)
        return AnalysisResult(observations=observations)
