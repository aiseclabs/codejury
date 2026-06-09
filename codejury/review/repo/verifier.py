"""Adversarial verification: try to REFUTE each candidate, keep the survivors.

High recall comes from the union of diverse passes, but that also lets false
positives and bounded-but-real-looking misreads through. This stage is the
precision counterweight, the part that earns the right to surface everything: each
candidate is handed to an independent skeptic whose job is to DISPROVE it by reading
the code, judging against production semantics, not a shallow read. A select_for_update
holds the row lock on a real RDBMS even if its result is discarded. A check defined in
a base class still fires on the subclass. A value an attacker cannot reach is not a
sink. A candidate that survives is confirmed. One refuted with a named controlling
fact is dropped and recorded, so the drop is auditable.

Injectable like the reviewer, so the skeptic can be a single grounded model call
today or a tool-using agent later. Errors never silently refute a finding: a failed
verification keeps the candidate and is counted, because dropping a real finding on a
failed call is the worst outcome for recall.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from codejury.json_parse import extract_json_object
from codejury.providers.base import Message, Provider
from codejury.resources import FALSE_POSITIVE_TRAPS_FILE
from codejury.review.repo.union import Candidate

_READ_MAX = 40_000   # chars of the cited file read for the skeptic


@dataclass(frozen=True, kw_only=True)
class Verdict:
    real: bool
    reason: str = ""


class Verifier(ABC):
    @abstractmethod
    def verify(self, candidate: Candidate, root: str) -> Verdict:
        """Try to refute one candidate. Return real or refuted, with the reason."""


@dataclass(frozen=True, kw_only=True)
class VerifyResult:
    confirmed: list[Candidate] = field(default_factory=list)
    refuted: list[tuple[Candidate, str]] = field(default_factory=list)
    errors: int = 0


_SYSTEM = (
    "You are a skeptical security reviewer. Your job is to REFUTE a proposed finding "
    "by reading the code: find the controlling fact that makes it safe, judging against "
    "production semantics, not a shallow read. Only if you genuinely cannot refute it is "
    "it real. Respond with a single JSON object and nothing else."
)

_JSON_SHAPE = '{"real": true, "reason": "the controlling fact at file:line, refuting or confirming"}'


def _read_file(root: str, rel: str) -> str:
    if not rel:
        return ""
    try:
        return (Path(root) / rel).read_text(encoding="utf-8")[:_READ_MAX]
    except (OSError, UnicodeDecodeError):
        return ""


class ModelVerifier(Verifier):
    """Default skeptic: one grounded model call that tries to refute the candidate."""

    def __init__(self, *, provider: Provider, model: str, max_tokens: int = 2048) -> None:
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens
        self._traps = FALSE_POSITIVE_TRAPS_FILE.read_text(encoding="utf-8")

    def verify(self, candidate: Candidate, root: str) -> Verdict:
        code = _read_file(root, candidate.file)
        prompt = (
            "Try to REFUTE this proposed finding. Read the code and decide whether a "
            "controlling fact makes it genuinely safe, judging against PRODUCTION "
            "semantics, not a shallow read.\n\n"
            f"Traps to check against, in both directions, refuting a real finding as "
            f"wrongly as confirming a safe one:\n{self._traps}\n\n"
            f"Proposed finding:\n- {candidate.title}\n- category: {candidate.category}\n"
            f"- endpoint: {candidate.endpoint}\n- location: {candidate.file}:{candidate.line}\n"
            f"- claimed evidence: {candidate.evidence}\n\n"
            f"Code at {candidate.file}:\n```\n{code}\n```\n\n"
            f"Respond with a single JSON object exactly like:\n{_JSON_SHAPE}"
        )
        # let a provider error raise: the orchestrator counts it and keeps the finding,
        # it must never silently refute a real one
        result = self._provider.complete(
            system=_SYSTEM,
            messages=[Message(role="user", content=prompt)],
            model=self._model,
            max_tokens=self._max_tokens,
            cache=True,
        )
        obj = extract_json_object(result.text)
        if not isinstance(obj, dict) or "real" not in obj:
            return Verdict(real=True, reason="unparseable verification, kept")
        return Verdict(real=bool(obj.get("real")), reason=str(obj.get("reason", "")))


def verify_findings(
    candidates: list[Candidate],
    verifier: Verifier,
    root: str,
    *,
    votes: int = 1,
    concurrency: int = 6,
) -> VerifyResult:
    """Verify every candidate, optionally with several independent votes per candidate.

    A candidate is refuted only when a majority of its COMPLETED votes refute it, so a
    single skeptic error cannot drop a finding. With no completed vote at all the
    candidate is kept and the error counted. Candidates are verified concurrently."""

    def verify_one(candidate: Candidate):
        verdicts: list[Verdict] = []
        errors = 0
        for _ in range(max(1, votes)):
            try:
                verdicts.append(verifier.verify(candidate, root))
            except Exception:
                errors += 1
        if not verdicts:
            return candidate, True, "", errors           # no vote completed, keep it
        refuted = sum(1 for v in verdicts if not v.real)
        if refuted * 2 > len(verdicts):                   # majority refuted
            reason = next((v.reason for v in verdicts if not v.real), "")
            return candidate, False, reason, errors
        return candidate, True, "", errors

    if concurrency > 1 and len(candidates) > 1:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            results = list(pool.map(verify_one, candidates))
    else:
        results = [verify_one(c) for c in candidates]

    confirmed = [c for c, real, _r, _e in results if real]
    refuted = [(c, reason) for c, real, reason, _e in results if not real]
    errors = sum(e for _c, _real, _r, e in results)
    return VerifyResult(confirmed=confirmed, refuted=refuted, errors=errors)
