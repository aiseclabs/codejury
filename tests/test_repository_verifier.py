"""The single verification route: refute candidates, drop only when every independent
confirmer upholds the refutation, never drop a finding on a failed call, decide by majority
when multiple votes are cast."""

import pytest

from codejury.providers.mock import MockProvider
from codejury.review.repository.union import Candidate
from codejury.review.repository.verifier import (
    ModelRefutationChecker,
    ModelVerifier,
    RefutationChecker,
    Verdict,
    Verifier,
    VerifyError,
    _read_file,
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


def _judge(checker):
    """The dedicated confirmer seat, empty label so it always applies, mirroring the cli."""
    return [("", checker)]


def test_a_refutation_alone_never_drops_a_finding_without_a_confirmer():
    cands = [Candidate(title="real1", endpoint="GET /a"),
             Candidate(title="fp", endpoint="GET /b")]
    vr = verify_findings(cands, StubVerifier(["fp"]), ".", concurrency=2)
    assert {c.title for c in vr.confirmed} == {"real1", "fp"}
    assert not vr.refuted


def test_drops_only_when_an_independent_confirmer_upholds_the_refutation():
    cands = [Candidate(title="real1", endpoint="GET /a"),
             Candidate(title="fp", endpoint="GET /b"),
             Candidate(title="real2", endpoint="GET /c")]
    vr = verify_findings(cands, StubVerifier(["fp"]), ".",
                         confirmers=_judge(StubChecker(["fp"])), concurrency=2)
    assert {c.title for c in vr.confirmed} == {"real1", "real2"}
    assert [c.title for c, _ in vr.refuted] == ["fp"]


def test_a_rejected_refutation_keeps_the_finding():
    # the skeptic refutes but the independent confirmer finds the controlling fact does not hold,
    # the rate==0 reason for a rate>0 bug, so the finding stays.
    cands = [Candidate(title="fp", endpoint="GET /b")]
    vr = verify_findings(cands, StubVerifier(["fp"]), ".", confirmers=_judge(StubChecker([])), concurrency=1)
    assert [c.title for c in vr.confirmed] == ["fp"]
    assert not vr.refuted


def test_a_drop_needs_every_applicable_confirmer_to_uphold_the_refutation():
    # two confirmers, one upholds and one does not, so the refutation is not unanimous and the
    # finding stays, the recall-safe rule that a single dissent saves it
    cands = [Candidate(title="fp", endpoint="GET /b")]
    confirmers = [("c1", StubChecker(["fp"])), ("c2", StubChecker([]))]
    vr = verify_findings(cands, StubVerifier(["fp"]), ".", confirmers=confirmers, concurrency=1)
    assert [c.title for c in vr.confirmed] == ["fp"] and not vr.refuted


def test_a_confirmer_that_found_the_finding_is_skipped_as_not_independent():
    # the only confirmer is the model that surfaced the finding, so it cannot give an independent
    # read, it is skipped and with no applicable confirmer left the finding is kept
    cands = [Candidate(title="fp", endpoint="GET /b", found_by=("c1",))]
    vr = verify_findings(cands, StubVerifier(["fp"]), ".",
                         confirmers=[("c1", StubChecker(["fp"]))], concurrency=1)
    assert [c.title for c in vr.confirmed] == ["fp"] and not vr.refuted
    # a second, independent confirmer that did not find it can drop it
    vr2 = verify_findings(cands, StubVerifier(["fp"]), ".",
                          confirmers=[("c1", StubChecker(["fp"])), ("c2", StubChecker(["fp"]))], concurrency=1)
    assert [c.title for c, _ in vr2.refuted] == ["fp"]


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


def test_a_confirmer_error_keeps_the_finding_incomplete_not_frozen():
    # every vote refuted, but the confirmer that must uphold a deletion raised, so the finding is
    # kept and marked incomplete rather than confirmed safe on a failed audit
    class BoomChecker(StubChecker):
        def holds(self, candidate, reason, root):
            raise RuntimeError("rate limited")

    vr = verify_findings([Candidate(title="fp", endpoint="GET /b")],
                         StubVerifier(["fp"]), ".", confirmers=_judge(BoomChecker([])), concurrency=1)
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


def test_every_vote_refuting_and_an_upholding_confirmer_drops_at_votes_above_one():
    vr = verify_findings([Candidate(title="fp", endpoint="GET /b")],
                         StubVerifier(["fp"]), ".", votes=3,
                         confirmers=_judge(StubChecker(["fp"])), concurrency=1)
    assert [c.title for c, _ in vr.refuted] == ["fp"] and not vr.confirmed


class RefuteThenKeepVerifier(Verifier):
    """Refutes the first two votes then keeps on the third, so one keep sits among three votes."""
    def __init__(self):
        self.i = 0

    def verify(self, candidate, root):
        self.i += 1
        return Verdict(real=(self.i == 3))


def test_one_keep_vote_saves_the_finding_even_with_an_upholding_confirmer():
    vr = verify_findings([Candidate(title="x", endpoint="GET /a")],
                         RefuteThenKeepVerifier(), ".", votes=3,
                         confirmers=_judge(StubChecker(["x"])), concurrency=1)
    assert [c.title for c in vr.confirmed] == ["x"] and not vr.refuted


def test_model_verifier_parses_a_refutation():
    prov = MockProvider(default='{"real": false, "reason": "the lock holds on a real RDBMS"}')
    verdict = ModelVerifier(provider=prov, model="mock").verify(
        Candidate(title="race", endpoint="POST /t", file=""), ".")
    assert verdict.real is False and "lock holds" in verdict.reason
    assert prov.calls[0]["cache"] is True


def test_model_verifier_keeps_a_refutation_citing_a_same_named_file_in_another_dir():
    prov = MockProvider(default='{"real": false, "control_file": "services/config.py"}')
    verdict = ModelVerifier(provider=prov, model="mock").verify(
        Candidate(title="x", endpoint="GET /a", file="models/config.py"), ".")
    assert verdict.real is True


def test_model_verifier_treats_a_bare_filename_control_as_on_file():
    prov = MockProvider(default='{"real": false, "control_file": "config.py"}')
    verdict = ModelVerifier(provider=prov, model="mock").verify(
        Candidate(title="x", endpoint="GET /a", file="models/config.py"), ".")
    assert verdict.real is False


def test_model_verifier_raises_on_unparseable_reply():
    # an unparseable verifier reply is a failed step, not a clean confirmation, invariant 4
    prov = MockProvider(default="no json here")
    with pytest.raises(VerifyError):
        ModelVerifier(provider=prov, model="mock").verify(Candidate(title="x"), ".")


def test_verify_findings_keeps_but_flags_an_unparseable_verification():
    # a verifier that cannot parse its reply keeps the finding for recall but marks it incomplete and
    # counts an error, so a resume re-attempts it instead of freezing an unverified confirmation
    prov = MockProvider(default="no json here")
    vr = verify_findings([Candidate(title="x", endpoint="GET /a")],
                         ModelVerifier(provider=prov, model="mock"), ".")
    assert [c.title for c in vr.confirmed] == ["x"]
    assert [c.title for c in vr.incomplete] == ["x"]
    assert vr.errors == 1


def test_model_verifier_keeps_a_refutation_that_rests_on_an_unshown_file():
    # a refutation that rests on an upstream check in a file the skeptic never read keeps the
    # finding, so a cross-file authorization gap is not dropped
    prov = MockProvider(default='{"real": false, "reason": "the service checks the owner", '
                        '"control_file": "internal/service/answer_service.go"}')
    verdict = ModelVerifier(provider=prov, model="mock").verify(
        Candidate(title="accept", file="internal/repository/activity/answer_repository.go"), ".")
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
    prov = MockProvider(default="not json")
    checker = ModelRefutationChecker(provider=prov, model="mock")
    assert checker.holds(Candidate(title="x", file=""), "some reason", ".") is False


def test_read_file_returns_empty_for_an_out_of_root_path(tmp_path):
    secret = tmp_path / "secret.py"
    secret.write_text("token = 'sk-live'")
    root = tmp_path / "repository"
    root.mkdir()
    assert _read_file(str(root), "../secret.py") == ""
    assert _read_file(str(root), str(secret)) == ""


def test_verify_findings_reports_progress_per_candidate():
    # on_verify fires once per candidate with a rising completion count, so the finalize
    # verify fan-out shows movement instead of hanging silent
    cands = [Candidate(title=f"c{i}", endpoint="GET /x") for i in range(4)]
    seen = []
    verify_findings(cands, StubVerifier([]), ".", concurrency=2,
                    on_verify=lambda done, total, secs: seen.append((done, total)))
    assert sorted(seen) == [(1, 4), (2, 4), (3, 4), (4, 4)]
