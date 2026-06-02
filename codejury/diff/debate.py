"""Adversarial diff audit: Finder, Challenger, Judge over the same diff.

Each round runs the three roles once: the finder scans, the challenger rebuts and
independently re-scans, the judge cross-validates and keeps the survivors. Rounds
repeat (feeding the judged set back to the finder) until the confirmed set is
stable or ``max_rounds`` is hit. Higher coverage and lower false positives than
the standard single call, at roughly three times the cost.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from codejury.diff.debate_prompts import (
    CHALLENGER_SYSTEM,
    FINDER_SYSTEM,
    JUDGE_SYSTEM,
    challenger_prompt,
    finder_prompt,
    judge_prompt,
)
from codejury.diff.rules import rules_for_diff
from codejury.domain.finding import Finding, findings_from_list
from codejury.infrastructure.json_parse import extract_json_object
from codejury.providers.base import Message, Provider


@dataclass(frozen=True, kw_only=True)
class AdversarialResult:
    findings: list[Finding]
    dismissed: list[dict] = field(default_factory=list)
    unresolved: list[dict] = field(default_factory=list)
    investigate: list[dict] = field(default_factory=list)
    rounds: int = 0
    converged: bool = False


def _dicts(items: object) -> list[dict]:
    return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []


def _key(f: Finding) -> tuple:
    return (f.file, f.line, f.category)


class AdversarialAuditRunner:
    def __init__(
        self,
        *,
        provider: Provider,
        model: str,
        max_tokens: int = 4096,
        finder_model: str | None = None,
        challenger_model: str | None = None,
        judge_model: str | None = None,
    ) -> None:
        self._provider = provider
        self._max_tokens = max_tokens
        # each role can run on its own model (a strong finder, a skeptical
        # challenger, a careful judge); each defaults to the base model.
        self._finder_model = finder_model or model
        self._challenger_model = challenger_model or model
        self._judge_model = judge_model or model

    def _ask(self, system: str, prompt: str, model: str) -> dict:
        result = self._provider.complete(
            system=system,
            messages=[Message(role="user", content=prompt)],
            model=model,
            max_tokens=self._max_tokens,
        )
        return extract_json_object(result.text) or {}

    def run(self, diff: str, *, rules: str = "", context: str = "", max_rounds: int = 3) -> AdversarialResult:
        if not rules:
            rules = rules_for_diff(diff)  # inject the rules relevant to this diff
        prior: list[dict] = []
        prev_keys: set | None = None
        judged = AdversarialResult(findings=[])
        rounds = 0
        converged = False
        for rounds in range(1, max_rounds + 1):
            finder = self._ask(
                FINDER_SYSTEM, finder_prompt(diff, rules=rules, context=context, prior=prior), self._finder_model
            )
            finder_findings = _dicts(finder.get("findings"))

            challenger = self._ask(
                CHALLENGER_SYSTEM,
                challenger_prompt(diff, finder_findings, rules=rules, context=context),
                self._challenger_model,
            )
            rebuttals = _dicts(challenger.get("rebuttals"))
            new_findings = _dicts(challenger.get("new_findings"))

            verdict = self._ask(
                JUDGE_SYSTEM,
                judge_prompt(diff, finder_findings, rebuttals, new_findings, context=context),
                self._judge_model,
            )
            judged = AdversarialResult(
                findings=findings_from_list(verdict.get("findings")),
                dismissed=_dicts(verdict.get("dismissed")),
                unresolved=_dicts(verdict.get("unresolved")),
                investigate=_dicts(verdict.get("investigate")),
                rounds=rounds,
            )

            keys = {_key(f) for f in judged.findings}
            if prev_keys is not None and keys == prev_keys:
                converged = True
                break
            prev_keys = keys
            prior = [f.to_dict() for f in judged.findings]

        return AdversarialResult(
            findings=judged.findings,
            dismissed=judged.dismissed,
            unresolved=judged.unresolved,
            investigate=judged.investigate,
            rounds=rounds,
            converged=converged,
        )
