"""Adversarial diff audit: Finder, Challenger, Judge over the same diff.

Each round runs the three roles once: the finder scans, the challenger rebuts and
independently re-scans, the judge cross-validates and keeps the survivors. Rounds
repeat, feeding the judged set back to the finder, until the confirmed set is
stable or ``max_rounds`` is hit. Higher coverage and lower false positives than
the standard single call, at roughly three times the cost.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from codejury.review.diff.adversarial_prompts import (
    CHALLENGER_SYSTEM,
    FINDER_SYSTEM,
    JUDGE_SYSTEM,
    challenger_prompt,
    finder_prompt,
    judge_prompt,
)
from codejury.review.diff.vulnerabilities import vulnerabilities_for_diff
from codejury.finding import Finding, findings_from_list
from codejury.json_parse import extract_json_object
from codejury.providers.base import Message, Provider


@dataclass(frozen=True, kw_only=True)
class AdversarialResult:
    findings: list[Finding]
    downgraded: list[dict] = field(default_factory=list)
    dismissed: list[dict] = field(default_factory=list)
    unresolved: list[dict] = field(default_factory=list)
    investigate: list[dict] = field(default_factory=list)
    rounds: int = 0
    converged: bool = False
    degraded: bool = False  # the judge response was unusable, findings are the unjudged fallback


def _dicts(items: object) -> list[dict]:
    return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []


def _key(f: Finding) -> tuple:
    return (f.file, f.line, f.category)


def _dedup(items: list[dict]) -> list[dict]:
    seen: set = set()
    out: list[dict] = []
    for d in items:
        k = (d.get("file"), d.get("line"), d.get("category"))
        if k not in seen:
            seen.add(k)
            out.append(d)
    return out


_DISMISS_VERDICTS = frozenset({"dismiss", "dismissed", "false_positive", "reject", "rejected"})


def _loc(d: dict) -> str:
    line = d.get("line")
    return f"{d.get('file')}:{line}" if line else str(d.get("file") or "")


def _apply_dismissals(findings: list[dict], rebuttals: list[dict]) -> list[dict]:
    """Drop findings the challenger dismissed. The challenger is recall-safe: it
    dismisses only when the diff shows a safe pattern such as a parameterized query,
    a basename, an allowlist, or shell=False, so honoring its dismissals is sound even
    when the judge is unavailable."""
    dismissed = {
        str(r.get("target")) for r in rebuttals
        if str(r.get("verdict", "")).strip().lower() in _DISMISS_VERDICTS
    }
    if not dismissed:
        return findings
    return [f for f in findings if _loc(f) not in dismissed and str(f.get("file") or "") not in dismissed]


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
        # each role can run on its own model, each defaults to the base model
        self._finder_model = finder_model or model
        self._challenger_model = challenger_model or model
        self._judge_model = judge_model or model

    def _ask(self, system: str, prompt: str, model: str) -> tuple[dict, bool]:
        """Return the parsed object and an ok flag. ok is False when the response
        could not be parsed into a JSON object, for example a provider error page,
        a blocked request, or prose, so the caller does not treat an unusable reply
        as an empty result."""
        try:
            result = self._provider.complete(
                system=system,
                messages=[Message(role="user", content=prompt)],
                model=model,
                max_tokens=self._max_tokens,
            )
        except Exception:
            # a provider error such as exhausted retries or a transport failure
            # is an unusable reply, not an empty result, so degrade gracefully
            return {}, False
        obj = extract_json_object(result.text)
        return (obj or {}), bool(obj)

    def run(self, diff: str, *, vulnerabilities: str = "", context: str = "", max_rounds: int = 3) -> AdversarialResult:
        if not vulnerabilities:
            vulnerabilities = vulnerabilities_for_diff(diff)
        prior: list[dict] = []
        prev_keys: set | None = None
        judged = AdversarialResult(findings=[])
        rounds = 0
        converged = False
        degraded = False
        for rounds in range(1, max_rounds + 1):
            finder, _ = self._ask(
                FINDER_SYSTEM, finder_prompt(diff, vulnerabilities=vulnerabilities, context=context, prior=prior), self._finder_model
            )
            finder_findings = _dicts(finder.get("findings"))

            challenger, _ = self._ask(
                CHALLENGER_SYSTEM,
                challenger_prompt(diff, finder_findings, vulnerabilities=vulnerabilities, context=context),
                self._challenger_model,
            )
            rebuttals = _dicts(challenger.get("rebuttals"))
            new_findings = _dicts(challenger.get("new_findings"))

            jp = judge_prompt(diff, finder_findings, rebuttals, new_findings, context=context)
            verdict, judge_ok = self._ask(JUDGE_SYSTEM, jp, self._judge_model)
            if not judge_ok:
                # the judge is the filter that controls false positives, and an
                # unusable reply is usually transient, so re-ask once before degrading
                verdict, judge_ok = self._ask(JUDGE_SYSTEM, jp, self._judge_model)
            if not judge_ok:
                # judge still unusable: degrade, but apply the recall-safe
                # challenger dismissals so a transient judge outage does not pass
                # through findings the challenger already showed are safe. without
                # this the degraded fallback inflates false positives
                fallback = _dedup(_apply_dismissals(finder_findings, rebuttals) + new_findings)
                judged = AdversarialResult(findings=findings_from_list(fallback), rounds=rounds, degraded=True)
                degraded = True
                break

            judged = AdversarialResult(
                findings=findings_from_list(verdict.get("findings")),
                downgraded=_dicts(verdict.get("downgraded")),
                dismissed=_dicts(verdict.get("dismissed")),
                unresolved=_dicts(verdict.get("unresolved")),
                investigate=_dicts(verdict.get("investigate")),
                rounds=rounds,
            )

            # converge when the Judge says so, or the confirmed set is unchanged
            # since last round, but only once nothing is left to investigate
            keys = {_key(f) for f in judged.findings}
            judge_converged = bool(verdict.get("converged", False))
            stable = prev_keys is not None and keys == prev_keys
            if (judge_converged or stable) and not judged.investigate:
                converged = True
                break
            prev_keys = keys
            prior = [f.to_dict() for f in judged.findings]

        return AdversarialResult(
            findings=judged.findings,
            degraded=degraded,
            downgraded=judged.downgraded,
            dismissed=judged.dismissed,
            unresolved=judged.unresolved,
            investigate=judged.investigate,
            rounds=rounds,
            converged=converged,
        )
