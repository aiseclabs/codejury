"""Standard diff-audit engine: one model call over a diff, parsed into Findings.

The cheap, balanced default. The adversarial Finder/Challenger/Judge engine
(RW-2) builds on the same Finding domain for the cases that need higher
coverage and lower false positives.
"""

from __future__ import annotations

from codejury.domain.finding import Finding, findings_from_list
from codejury.diff.prompts import SYSTEM, standard_audit_prompt
from codejury.diff.rules import rules_for_diff
from codejury.infrastructure.json_parse import extract_json_object
from codejury.providers.base import Message, Provider


class AuditError(RuntimeError):
    """The model reply could not be parsed into an audit result.

    Raised instead of returning an empty findings list, so a failed or blank
    call is never reported as a clean audit. The prompt requires a JSON object
    carrying a ``findings`` key (an empty ``{"findings": []}`` when there is
    nothing to report), so a reply that yields no object, or an object without
    that key, is a failure, not a pass."""


class AuditRunner:
    def __init__(self, *, provider: Provider, model: str, max_tokens: int = 4096) -> None:
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens

    def run(self, diff: str, *, rules: str = "", context: str = "") -> list[Finding]:
        if not rules:
            rules = rules_for_diff(diff)  # inject the rules relevant to this diff
        result = self._provider.complete(
            system=SYSTEM,
            messages=[Message(role="user", content=standard_audit_prompt(diff, rules=rules, context=context))],
            model=self._model,
            max_tokens=self._max_tokens,
        )
        obj = extract_json_object(result.text)
        if obj is None or "findings" not in obj:
            raise AuditError(
                "the model reply was not a valid audit result (no JSON object, or a "
                "JSON object without a `findings` key); treating it as a failed "
                "audit rather than a clean pass"
            )
        return findings_from_list(obj.get("findings"))
