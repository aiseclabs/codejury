"""The adversarial verification stage: refute candidates, keep survivors, never drop
a finding on a failed call, decide by majority when multiple votes are cast."""

from codejury.providers.mock import MockProvider
from codejury.review.repo.union import Candidate
from codejury.review.repo.verify import ModelVerifier, Verdict, Verifier, verify_findings


class StubVerifier(Verifier):
    def __init__(self, refute_titles):
        self.refute = set(refute_titles)

    def verify(self, candidate, root):
        bad = candidate.title in self.refute
        return Verdict(real=not bad, reason="controlling fact holds" if bad else "")


def test_verify_keeps_survivors_drops_refuted():
    cands = [Candidate(title="real1", endpoint="GET /a"),
             Candidate(title="fp", endpoint="GET /b"),
             Candidate(title="real2", endpoint="GET /c")]
    vr = verify_findings(cands, StubVerifier(["fp"]), ".", concurrency=2)
    assert {c.title for c in vr.confirmed} == {"real1", "real2"}
    assert [c.title for c, _ in vr.refuted] == ["fp"]


class FlakyVerifier(Verifier):
    def verify(self, candidate, root):
        if candidate.title == "boom":
            raise RuntimeError("rate limited")
        return Verdict(real=False, reason="would refute")


def test_error_keeps_finding_and_is_counted_never_silently_refuted():
    vr = verify_findings([Candidate(title="boom", endpoint="GET /a")],
                         FlakyVerifier(), ".", votes=1, concurrency=1)
    assert vr.errors >= 1
    assert [c.title for c in vr.confirmed] == ["boom"]   # kept on error, not dropped
    assert not vr.refuted


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
    assert [c.title for c in vr.confirmed] == ["x"]      # 2 real vs 1 refute -> kept


def test_model_verifier_parses_a_refutation():
    prov = MockProvider(default='{"real": false, "reason": "the lock holds on a real RDBMS"}')
    verdict = ModelVerifier(provider=prov, model="mock").verify(
        Candidate(title="race", endpoint="POST /t", file=""), ".")
    assert verdict.real is False and "lock holds" in verdict.reason


def test_model_verifier_keeps_on_unparseable_reply():
    prov = MockProvider(default="no json here")
    verdict = ModelVerifier(provider=prov, model="mock").verify(Candidate(title="x"), ".")
    assert verdict.real is True   # unparseable verification keeps the finding, never refutes it
