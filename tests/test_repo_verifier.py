"""The adversarial verification stage: refute candidates, keep survivors, never drop
a finding on a failed call, decide by majority when multiple votes are cast."""

from codejury.providers.mock import MockProvider
from codejury.review.repo.union import Candidate
from codejury.review.repo.verifier import (
    Assessment,
    Judge,
    ModelRefutationChecker,
    ModelVerifier,
    RefutationChecker,
    Verdict,
    Verifier,
    _read_file,
    cross_confirm,
    verify_findings,
)


class StubVerifier(Verifier):
    def __init__(self, refute_titles):
        self.refute = set(refute_titles)

    def verify(self, candidate, root):
        bad = candidate.title in self.refute
        return Verdict(real=not bad, reason="controlling fact holds" if bad else "")


class StubChecker(RefutationChecker):
    """Confirms the refutation only for the named titles, so a deletion needs this independent
    second read to agree, mirroring the production checker."""
    def __init__(self, holds_titles):
        self.h = set(holds_titles)

    def holds(self, candidate, reason, root):
        return candidate.title in self.h


def test_a_refutation_alone_never_drops_a_finding_without_a_checker():
    # a single skeptic opinion can no longer delete, the M-01 red-line fix: with no independent
    # checker every refutation is kept pending evidence.
    cands = [Candidate(title="real1", endpoint="GET /a"),
             Candidate(title="fp", endpoint="GET /b")]
    vr = verify_findings(cands, StubVerifier(["fp"]), ".", concurrency=2)
    assert {c.title for c in vr.confirmed} == {"real1", "fp"}
    assert not vr.refuted


def test_drops_only_when_an_independent_checker_confirms_the_refutation():
    cands = [Candidate(title="real1", endpoint="GET /a"),
             Candidate(title="fp", endpoint="GET /b"),
             Candidate(title="real2", endpoint="GET /c")]
    vr = verify_findings(cands, StubVerifier(["fp"]), ".",
                         checker=StubChecker(["fp"]), concurrency=2)
    assert {c.title for c in vr.confirmed} == {"real1", "real2"}
    assert [c.title for c, _ in vr.refuted] == ["fp"]


def test_a_rejected_refutation_keeps_the_finding():
    # the skeptic refutes but the independent checker finds the controlling fact does not hold,
    # the rate==0 reason for a rate>0 bug, so the finding stays.
    cands = [Candidate(title="fp", endpoint="GET /b")]
    vr = verify_findings(cands, StubVerifier(["fp"]), ".", checker=StubChecker([]), concurrency=1)
    assert [c.title for c in vr.confirmed] == ["fp"]
    assert not vr.refuted


class FlakyVerifier(Verifier):
    def verify(self, candidate, root):
        if candidate.title == "boom":
            raise RuntimeError("rate limited")
        return Verdict(real=False, reason="would refute")


def test_error_keeps_finding_and_is_counted_never_silently_refuted():
    vr = verify_findings([Candidate(title="boom", endpoint="GET /a")],
                         FlakyVerifier(), ".", votes=1, concurrency=1)
    assert vr.errors >= 1
    assert [c.title for c in vr.confirmed] == ["boom"]
    assert not vr.refuted
    # the keep was forced by the failure, so it is reported incomplete, not a confirmation, so a
    # resume re-attempts it rather than freezing the failure as kept
    assert [c.title for c in vr.incomplete] == ["boom"]


def test_a_checker_error_keeps_the_finding_incomplete_not_frozen():
    # every vote refuted, but the checker that must confirm a deletion raised, so the finding is
    # kept and marked incomplete rather than confirmed safe on a failed audit
    class BoomChecker(StubChecker):
        def holds(self, candidate, reason, root):
            raise RuntimeError("rate limited")

    vr = verify_findings([Candidate(title="fp", endpoint="GET /b")],
                         StubVerifier(["fp"]), ".", checker=BoomChecker([]), concurrency=1)
    assert [c.title for c in vr.confirmed] == ["fp"]
    assert [c.title for c in vr.incomplete] == ["fp"]
    assert vr.errors >= 1


class SequenceVerifier(Verifier):
    """Returns real, real, refuted in sequence, so 3 votes are 2-1 in favour of real."""
    def __init__(self):
        self.i = 0

    def verify(self, candidate, root):
        self.i += 1
        return Verdict(real=(self.i % 3 != 0))


def test_majority_vote_keeps_when_only_a_minority_refutes():
    vr = verify_findings([Candidate(title="x", endpoint="GET /a")],
                         SequenceVerifier(), ".", votes=3, concurrency=1)
    assert [c.title for c in vr.confirmed] == ["x"]


def test_model_verifier_parses_a_refutation():
    prov = MockProvider(default='{"real": false, "reason": "the lock holds on a real RDBMS"}')
    verdict = ModelVerifier(provider=prov, model="mock").verify(
        Candidate(title="race", endpoint="POST /t", file=""), ".")
    assert verdict.real is False and "lock holds" in verdict.reason


def test_model_verifier_keeps_on_unparseable_reply():
    prov = MockProvider(default="no json here")
    verdict = ModelVerifier(provider=prov, model="mock").verify(Candidate(title="x"), ".")
    assert verdict.real is True


def test_model_verifier_keeps_a_refutation_that_rests_on_an_unshown_file():
    # the cross-file authorization gap the skeptic used to drop by trusting an upstream
    # check it never read, so a refutation citing another file keeps the finding
    prov = MockProvider(default='{"real": false, "reason": "the service checks the owner", '
                        '"control_file": "internal/service/answer_service.go"}')
    verdict = ModelVerifier(provider=prov, model="mock").verify(
        Candidate(title="accept", file="internal/repo/activity/answer_repo.go"), ".")
    assert verdict.real is True
    assert "answer_service.go" in verdict.reason


def test_model_verifier_refutes_on_a_fact_in_the_shown_file():
    prov = MockProvider(default='{"real": false, "reason": "owner filter present", '
                        '"control_file": "models/item.go"}')
    verdict = ModelVerifier(provider=prov, model="mock").verify(
        Candidate(title="idor", file="models/item.go"), ".")
    assert verdict.real is False


def test_model_checker_confirms_a_holding_refutation():
    prov = MockProvider(default='{"holds": true, "reason": "the guard dominates the only path"}')
    checker = ModelRefutationChecker(provider=prov, model="mock")
    assert checker.holds(Candidate(title="x", file=""), "owner check present", ".") is True


def test_model_checker_keeps_the_finding_on_an_unparseable_audit():
    # an audit that cannot be read cannot confirm the refutation, so the finding stays
    prov = MockProvider(default="not json")
    checker = ModelRefutationChecker(provider=prov, model="mock")
    assert checker.holds(Candidate(title="x", file=""), "some reason", ".") is False


def test_read_file_returns_empty_for_an_out_of_root_path(tmp_path):
    secret = tmp_path / "secret.py"
    secret.write_text("token = 'sk-live'")
    root = tmp_path / "repo"
    root.mkdir()
    assert _read_file(str(root), "../secret.py") == ""
    assert _read_file(str(root), str(secret)) == ""


class StubJudge(Judge):
    """Returns a fixed stance, modelling one model's second opinion on another's finding."""
    def __init__(self, stance, reason=""):
        self._stance = stance
        self._reason = reason

    def assess(self, candidate, root):
        return Assessment(stance=self._stance, reason=self._reason)


def test_cross_confirm_promotes_on_confirm():
    # a singleton found by claude, confirmed by gpt, becomes a two-model consensus
    c = Candidate(title="x", endpoint="GET /a", found_by=("claude",))
    cr = cross_confirm([c], [("claude", StubJudge("confirm")), ("gpt", StubJudge("confirm"))], ".")
    assert not cr.dropped
    (kept,) = cr.kept
    assert set(kept.found_by) == {"claude", "gpt"}


def test_cross_confirm_drops_on_dispute_by_the_other_model():
    c = Candidate(title="fp", endpoint="GET /a", found_by=("claude",))
    cr = cross_confirm([c], [("claude", StubJudge("confirm")), ("gpt", StubJudge("dispute", "guard at f:10"))], ".")
    assert not cr.kept
    assert [t for (cand, _r) in cr.dropped for t in [cand.title]] == ["fp"]


def test_cross_confirm_keeps_on_unsure():
    c = Candidate(title="maybe", endpoint="GET /a", found_by=("claude",))
    cr = cross_confirm([c], [("claude", StubJudge("confirm")), ("gpt", StubJudge("unsure"))], ".")
    assert [k.title for k in cr.kept] == ["maybe"] and not cr.dropped


class RaisingJudge(Judge):
    def assess(self, candidate, root):
        raise RuntimeError("rate limited")


def test_cross_confirm_keeps_and_counts_on_judge_error():
    # a failed judge keeps the finding and counts the error, never drops it, invariant 3, but it is
    # reported as errored not kept, so a resume re-adjudicates rather than freezing the failure
    c = Candidate(title="boom", endpoint="GET /a", found_by=("claude",))
    cr = cross_confirm([c], [("claude", StubJudge("confirm")), ("gpt", RaisingJudge())], ".", concurrency=1)
    assert not cr.kept and not cr.dropped
    assert [k.title for k in cr.errored] == ["boom"] and cr.errors >= 1
