"""The pass-loop orchestration and the per-unit reviewer.

The pass-loop is the deterministic core: it runs the whole worklist every pass,
cycles lenses, unions, and stops on convergence. Tested with a mock reviewer so the
orchestration is verified without a model. The default ModelReviewer's parsing is
tested with a mock provider."""

from codejury.providers.mock import MockProvider
from codejury.review.repo.passloop import run_passes
from codejury.review.repo.reviewer import ModelReviewer, Unit, UnitReviewer, candidates_from_obj
from codejury.review.repo.union import Candidate

_U = [Unit(name="u", root=".", files=())]


class LensReviewer(UnitReviewer):
    """Returns a fixed candidate set per lens, so the union is what the lenses cover."""
    def __init__(self, by_lens):
        self.by_lens = by_lens
        self.lenses_seen = []

    def review(self, unit, lens, *, shared_context=""):
        self.lenses_seen.append(lens)
        return list(self.by_lens.get(lens, []))


class NewEachPassReviewer(UnitReviewer):
    """Never converges: every call yields a brand-new finding."""
    def __init__(self):
        self.n = 0

    def review(self, unit, lens, *, shared_context=""):
        self.n += 1
        return [Candidate(title=f"f{self.n}", endpoint=f"GET /{self.n}")]


def test_lenses_cycle_and_union_converges_then_stops_early():
    a = Candidate(title="a", endpoint="GET /1")
    b = Candidate(title="b", endpoint="GET /2")
    reviewer = LensReviewer({"x": [a], "y": [b]})
    acc = run_passes(_U, reviewer, lenses=("x", "y"), converge_after=2, max_passes=24)

    assert {c.title for c in acc.findings} == {"a", "b"}     # union of both lenses
    assert acc.converged
    assert reviewer.lenses_seen == ["x", "y", "x", "y"]      # cycled, stopped early at 4 passes
    assert acc.new_per_pass == [1, 1, 0, 0]                  # grew, then two empty -> converged


def test_runs_to_max_passes_when_never_converges():
    reviewer = NewEachPassReviewer()
    acc = run_passes(_U, reviewer, lenses=("",), converge_after=2, max_passes=5)
    assert not acc.converged
    assert len(acc.new_per_pass) == 5                        # never stops early
    assert len(acc.findings) == 5


class PerUnitReviewer(UnitReviewer):
    """One distinct finding per unit, so merge order is observable."""
    def review(self, unit, lens, *, shared_context=""):
        return [Candidate(title=unit.name, endpoint=f"GET /{unit.name}")]


def test_concurrency_yields_same_union_as_serial():
    units = [Unit(name=f"u{i}", root=".", files=()) for i in range(6)]
    serial = run_passes(units, PerUnitReviewer(), lenses=("",), concurrency=1, max_passes=3)
    parallel = run_passes(units, PerUnitReviewer(), lenses=("",), concurrency=4, max_passes=3)
    assert {c.key() for c in serial.findings} == {c.key() for c in parallel.findings}
    assert len(parallel.findings) == 6   # one per unit, no loss under concurrency


class FlakyReviewer(UnitReviewer):
    """Raises on one unit, like a rate-limited call, returns findings on the others."""
    def review(self, unit, lens, *, shared_context=""):
        if unit.name == "bad":
            raise RuntimeError("rate limited")
        return [Candidate(title=unit.name, endpoint=f"GET /{unit.name}")]


def test_unit_failures_are_counted_not_silent():
    units = [Unit(name="ok1", root=".", files=()),
             Unit(name="bad", root=".", files=()),
             Unit(name="ok2", root=".", files=())]
    acc = run_passes(units, FlakyReviewer(), lenses=("",), concurrency=2, max_passes=2)
    assert acc.errors >= 1                                   # the failure was surfaced, not swallowed
    assert {c.title for c in acc.findings} == {"ok1", "ok2"}  # a failing unit does not abort the others


def test_candidates_from_obj_is_tolerant():
    obj = {"findings": [
        {"title": "real", "severity": "CRITICAL", "endpoint": "POST /t", "category": "idor"},
        {"no_title": 1},     # dropped, no title
        "junk",              # dropped, not a dict
    ]}
    cands = candidates_from_obj(obj)
    assert len(cands) == 1
    assert cands[0].severity == "CRITICAL" and cands[0].endpoint == "POST /t"


def test_candidates_default_severity_is_medium_not_dropped():
    # a finding with a junk severity is kept at MEDIUM, never silently dropped
    cands = candidates_from_obj({"findings": [{"title": "x", "severity": "spicy"}]})
    assert len(cands) == 1 and cands[0].severity == "MEDIUM"


def test_model_reviewer_builds_prompt_and_parses(tmp_path):
    (tmp_path / "app.py").write_text("def handler():\n    return 'ok'\n")
    reply = ('{"findings": [{"title": "idor", "category": "idor", '
             '"endpoint": "GET /x/<id>", "file": "app.py", "line": 2, '
             '"severity": "high", "status": "confirmed"}]}')
    prov = MockProvider(default=reply)
    reviewer = ModelReviewer(provider=prov, model="mock")
    unit = Unit(name="wallets", root=str(tmp_path), files=("app.py",))

    cands = reviewer.review(unit, "authorization", shared_context="stack: flask")
    assert len(cands) == 1
    assert cands[0].endpoint == "GET /x/<id>" and cands[0].severity == "HIGH"

    sent = prov.calls[0]["messages"][0].content
    assert "AUTHORIZATION LENS" in sent          # the pass lens
    assert "Severity rubric" in sent             # the rubric is embedded
    assert "def handler" in sent                 # the unit's code was gathered in


def test_model_reviewer_empty_on_unparseable_reply():
    prov = MockProvider(default="sorry, no JSON here")
    reviewer = ModelReviewer(provider=prov, model="mock")
    assert reviewer.review(Unit(name="u", root=".", files=()), "") == []
