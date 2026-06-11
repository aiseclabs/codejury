"""The adversarial verification stage: refute candidates, keep survivors, never drop
a finding on a failed call, decide by majority when multiple votes are cast."""

from codejury.providers.mock import MockProvider
from codejury.review.repo.union import Candidate
from codejury.review.repo.verifier import ModelVerifier, Verdict, Verifier, _read_file, verify_findings


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
    assert [c.title for c in vr.confirmed] == ["boom"]
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


def test_read_file_returns_empty_for_an_out_of_root_path(tmp_path):
    secret = tmp_path / "secret.py"
    secret.write_text("token = 'sk-live'")
    root = tmp_path / "repo"
    root.mkdir()
    assert _read_file(str(root), "../secret.py") == ""
    assert _read_file(str(root), str(secret)) == ""
