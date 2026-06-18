"""Adversarial verification: try to REFUTE each candidate, drop only a confirmed refutation.

High recall comes from the union of diverse passes, but that also lets false
positives and bounded-but-real-looking misreads through. This stage is the
precision counterweight, the part that earns the right to surface everything: each
candidate is handed to an independent skeptic whose job is to DISPROVE it by reading
the code, judging against production semantics, not a shallow read. A select_for_update
holds the row lock on a real RDBMS even if its result is discarded. A check defined in
a base class still fires on the subclass. A value an attacker cannot reach is not a
sink. A candidate that survives is confirmed.

A refutation alone is an opinion, not a deletion, and a single skeptic that misreads
drops a real finding, the worst outcome for recall. So a refuted candidate is dropped
only when a second independent read, the `RefutationChecker`, confirms the controlling
fact genuinely neutralizes the finding on its real path, the rate==0 reason rejected for
a bug that bites at rate>0. With no checker, no confirmation, or any keep vote, the
finding stays. Every drop is recorded, so it is auditable.

The skeptic sees only the finding's own file, so a refutation that rests on a control
in another file it was not shown is an assumption, not a refutation, the failure that
dropped a real cross-file authorization gap by trusting an upstream check that did not
exist. Such a finding is kept for cross-file confirmation, not dropped.

Injectable like the reviewer, so the skeptic can be a single grounded model call
today or a tool-using agent later. Errors never silently refute a finding: a failed
verification keeps the candidate and is counted, because dropping a real finding on a
failed call is the worst outcome for recall.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace

from codejury.domains.base import ContentPaths
from codejury.json_parse import optional_json_object
from codejury.providers.base import Message, Provider
from codejury.resources import FALSE_POSITIVE_TRAPS_FILE
from codejury.review.repo.paths import safe_repo_path
from codejury.review.repo.union import Candidate

_READ_MAX = 40_000


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
    "production semantics, not a shallow read. You are shown only the code at the finding's "
    "own file, so you may refute only on a fact visible in that code or a genuine framework "
    "guarantee. When the finding would be safe only because of a control in another file you "
    "were not shown, an upstream service or controller you assume enforces it for example, you "
    "have not refuted it: report it real and name that other file in control_file. Only if you "
    "genuinely cannot refute it is it real. Respond with a single JSON object and nothing else."
)

_JSON_SHAPE = (
    '{"real": true, "reason": "the controlling fact at file:line", '
    '"control_file": "the file holding that fact, empty if none"}'
)


def _control_basename(ref: str) -> str:
    """The file name a controlling fact cites, without its directory or a trailing line,
    empty when the skeptic named none."""
    ref = ref.strip().strip("`").split(":", 1)[0].strip()
    return ref.rsplit("/", 1)[-1] if ref else ""


def _read_file(root: str, rel: str) -> str:
    path = safe_repo_path(root, rel)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")[:_READ_MAX]
    except (OSError, UnicodeDecodeError):
        return ""


class ModelVerifier(Verifier):
    """Default skeptic: one grounded model call that tries to refute the candidate."""

    def __init__(self, *, provider: Provider, model: str, max_tokens: int = 2048,
                 content: ContentPaths | None = None) -> None:
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens
        traps_file = content.false_positive_traps_file if content else FALSE_POSITIVE_TRAPS_FILE
        self._traps = traps_file.read_text(encoding="utf-8")

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
        result = self._provider.complete(
            system=_SYSTEM,
            messages=[Message(role="user", content=prompt)],
            model=self._model,
            max_tokens=self._max_tokens,
            cache=True,
        )
        obj, ok = optional_json_object(result.text, required_key="real")
        if not ok:
            return Verdict(real=True, reason="unparseable verification, kept")
        if obj.get("real"):
            return Verdict(real=True, reason=str(obj.get("reason", "")))
        control = _control_basename(str(obj.get("control_file", "")))
        if control and control != _control_basename(candidate.file):
            # the refutation rests on a file the skeptic was not shown, so it is an
            # assumption, not a refutation: keep the finding for cross-file confirmation
            return Verdict(real=True, reason=f"refuted on unshown {control}, kept for cross-file check")
        return Verdict(real=False, reason=str(obj.get("reason", "")))


class RefutationChecker(ABC):
    @abstractmethod
    def holds(self, candidate: Candidate, reason: str, root: str) -> bool:
        """Independently check whether a refutation's controlling fact genuinely neutralizes
        the finding on its real exploit path. True only when it clearly does, so a deletion
        rests on confirmed evidence, not a single skeptic's opinion."""


_CHECK_SYSTEM = (
    "You audit a proposed refutation, not the finding. A reviewer claims a security finding is "
    "safe because of one controlling fact. Assume the finding is REAL and try to show the fact "
    "does not actually neutralize it: the fact may be true yet guard a different path, a "
    "different precondition, or a different function than the one the finding exploits, the "
    "rate==0 branch when the bug bites at rate>0. Read the code at the finding's file. Conclude "
    "the refutation holds only when the controlling fact clearly and completely makes the "
    "finding unexploitable on its real path. Any doubt, any gap, the refutation does not hold "
    "and the finding stays. Respond with a single JSON object and nothing else."
)

_CHECK_SHAPE = '{"holds": true, "reason": "why the controlling fact does or does not neutralize the finding"}'


class ModelRefutationChecker(RefutationChecker):
    """Default checker: one independent grounded call that audits whether a refutation holds.

    A different angle from the skeptic, defending the finding rather than refuting it, so a
    deletion needs two independent reads to agree, not one skeptic's possibly shared blind spot."""

    def __init__(self, *, provider: Provider, model: str, max_tokens: int = 1024) -> None:
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens

    def holds(self, candidate: Candidate, reason: str, root: str) -> bool:
        code = _read_file(root, candidate.file)
        prompt = (
            "Audit this refutation. Does the controlling fact genuinely make the finding "
            "unexploitable on its real path, or does it guard a different path or precondition?\n\n"
            f"Finding:\n- {candidate.title}\n- category: {candidate.category}\n"
            f"- location: {candidate.file}:{candidate.line}\n- claimed evidence: {candidate.evidence}\n\n"
            f"Refutation's controlling fact, the reason it is called safe:\n{reason}\n\n"
            f"Code at {candidate.file}:\n```\n{code}\n```\n\n"
            f"Respond with a single JSON object exactly like:\n{_CHECK_SHAPE}"
        )
        result = self._provider.complete(
            system=_CHECK_SYSTEM,
            messages=[Message(role="user", content=prompt)],
            model=self._model,
            max_tokens=self._max_tokens,
            cache=True,
        )
        obj, ok = optional_json_object(result.text, required_key="holds")
        # an unreadable audit cannot confirm the refutation, so the finding stays, the red line
        if not ok:
            return False
        return bool(obj.get("holds"))


def verify_findings(
    candidates: list[Candidate],
    verifier: Verifier,
    root: str,
    *,
    checker: RefutationChecker | None = None,
    votes: int = 1,
    concurrency: int = 6,
) -> VerifyResult:
    """Verify every candidate. A finding is dropped only when every completed skeptic vote
    refutes it AND an independent `checker` confirms the refutation's controlling fact truly
    neutralizes it. Any keep vote saves it, asymmetric since dropping a real finding is the
    worst outcome for recall. With no completed vote, a failed check, or no checker at all the
    finding is kept, so a single opinion or a shared blind spot can never drop it. The error is
    counted, never read as a refutation. Candidates are verified concurrently."""

    def verify_one(candidate: Candidate):
        verdicts: list[Verdict] = []
        errors = 0
        for _ in range(max(1, votes)):
            try:
                verdicts.append(verifier.verify(candidate, root))
            except Exception:
                errors += 1
        # asymmetric keep: one vote that cannot refute saves the finding, and with no completed
        # vote at all it is kept and the error counted
        if not verdicts or any(v.real for v in verdicts):
            return candidate, True, "", errors
        # every completed vote refuted it, still only an opinion. A deletion needs an independent
        # checker to confirm the controlling fact genuinely neutralizes the finding, invariant 3.
        reason = next((v.reason for v in verdicts if not v.real), "")
        if checker is None:
            return candidate, True, "", errors
        try:
            confirmed_safe = checker.holds(candidate, reason, root)
        except Exception:
            return candidate, True, "", errors + 1
        if confirmed_safe:
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


@dataclass(frozen=True, kw_only=True)
class Assessment:
    stance: str   # "confirm" | "dispute" | "unsure"
    reason: str = ""


class Judge(ABC):
    @abstractmethod
    def assess(self, candidate: Candidate, root: str) -> Assessment:
        """Independently judge a finding another model surfaced: confirm, dispute, or unsure."""


_JUDGE_SYSTEM = (
    "You are a security reviewer giving an INDEPENDENT second opinion on a finding another "
    "reviewer reported. Read the code at the finding's file and judge on production semantics: "
    "confirm if you agree it is a real, exploitable issue, dispute if you can show it is safe and "
    "name the exact controlling fact and where it lives, unsure if you genuinely cannot tell. Do "
    "not confirm just to agree, nor dispute just to seem rigorous, judge the code. Dispute only "
    "when the controlling fact clearly neutralizes the finding on its real path, any doubt is "
    "unsure not dispute, since dropping a real finding is the worst outcome. Respond with a single "
    "JSON object and nothing else."
)

_JUDGE_SHAPE = ('{"stance": "confirm|dispute|unsure", "reason": "the controlling fact at file:line, '
                'or why it is real"}')


class ModelJudge(Judge):
    """A second opinion from one model: confirm, dispute, or unsure on another model's finding."""

    def __init__(self, *, provider: Provider, model: str, max_tokens: int = 2048) -> None:
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens

    def assess(self, candidate: Candidate, root: str) -> Assessment:
        code = _read_file(root, candidate.file)
        prompt = (
            "Give an independent second opinion on this finding. Read the code and decide: "
            "confirm, dispute, or unsure.\n\n"
            f"Finding:\n- {candidate.title}\n- category: {candidate.category}\n"
            f"- location: {candidate.file}:{candidate.line}\n- claimed evidence: {candidate.evidence}\n\n"
            f"Code at {candidate.file}:\n```\n{code}\n```\n\n"
            f"Respond with a single JSON object exactly like:\n{_JUDGE_SHAPE}"
        )
        result = self._provider.complete(
            system=_JUDGE_SYSTEM,
            messages=[Message(role="user", content=prompt)],
            model=self._model,
            max_tokens=self._max_tokens,
            cache=True,
        )
        obj, ok = optional_json_object(result.text, required_key="stance")
        if not ok:
            return Assessment(stance="unsure", reason="unparseable assessment, kept")
        stance = str(obj.get("stance", "")).strip().lower()
        if stance not in ("confirm", "dispute", "unsure"):
            stance = "unsure"
        return Assessment(stance=stance, reason=str(obj.get("reason", "")))


@dataclass(frozen=True, kw_only=True)
class CrossResult:
    kept: list = field(default_factory=list)
    dropped: list = field(default_factory=list)   # (candidate, reason)
    errors: int = 0


def cross_confirm(candidates: list[Candidate], judges: list, root: str, *,
                  concurrency: int = 6) -> CrossResult:
    """Adjudicate each finding with a model that did NOT surface it, the most independent second
    read. Confirm promotes it to a cross-model consensus, recorded on `found_by`. A clear dispute,
    a different model naming a controlling fact, drops it. Anything else, unsure, an error, or no
    available judge, keeps it, since dropping a real finding is the worst outcome for recall.
    `judges` is a list of (label, Judge), the label matching a model name on `found_by`."""

    def one(c: Candidate):
        others = [(lbl, j) for lbl, j in judges if lbl not in set(c.found_by)]
        if not others:
            return "keep", c, ""   # every configured model already found it, already a consensus
        lbl, judge = others[0]
        try:
            a = judge.assess(c, root)
        except Exception:
            return "error", c, ""
        if a.stance == "dispute":
            return "drop", c, a.reason
        if a.stance == "confirm":
            return "keep", replace(c, found_by=tuple(sorted(set(c.found_by) | {lbl}))), ""
        return "keep", c, ""   # unsure

    if concurrency > 1 and len(candidates) > 1:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            results = list(pool.map(one, candidates))
    else:
        results = [one(c) for c in candidates]

    kept = [c for verdict, c, _r in results if verdict in ("keep", "error")]
    dropped = [(c, r) for verdict, c, r in results if verdict == "drop"]
    errors = sum(1 for verdict, _c, _r in results if verdict == "error")
    return CrossResult(kept=kept, dropped=dropped, errors=errors)
