"""Regression tests for the full-repo code-review fixes."""
import json

import pytest

from codejury.domain.observation import Evidence, Finding, Verdict, is_problem, observation_from_dict


def test_observation_from_dict_unknown_kind_raises_valueerror():
    with pytest.raises(ValueError):
        observation_from_dict({"kind": "bogus", "capability": "x"})


def test_observation_from_dict_tolerates_extra_keys():
    # forward-compat: a newer field in a cached/baseline report must not crash an older loader
    d = {"kind": "verdict", "capability": "a.b", "status": "SECURE", "future_field": 1}
    obs = observation_from_dict(d)
    assert isinstance(obs, Verdict) and obs.status == "SECURE"


def test_observation_from_dict_filters_unknown_evidence_keys():
    d = {"kind": "finding", "capability": "a", "title": "t",
         "evidence": [{"file": "x.py", "line": 2, "extra": "drop me"}]}
    obs = observation_from_dict(d)
    assert obs.evidence[0].file == "x.py" and obs.evidence[0].line == 2


def test_is_problem_shared_predicate():
    assert is_problem(Finding(capability="a", title="t"))
    assert is_problem(Verdict(capability="a", status="VULNERABLE"))
    assert is_problem(Verdict(capability="a", status="PARTIAL"))
    assert not is_problem(Verdict(capability="a", status="SECURE"))


def test_capability_rejects_bad_severity(tmp_path):
    from codejury.domain.capability import load_capability
    bad = tmp_path / "c.yaml"
    bad.write_text(
        "id: x\nname: X\nsub_capabilities:\n  s:\n    anti_patterns:\n"
        "      - {id: A, severity: Hihg}\n"
    )
    with pytest.raises(ValueError) as e:
        load_capability(bad)
    assert "severity" in str(e.value) and str(bad) in str(e.value)


def test_from_json_rejects_malformed_baseline():
    from codejury.reporting import from_json
    with pytest.raises(ValueError):
        from_json("not json")
    with pytest.raises(ValueError):
        from_json("[1, 2, 3]")  # not an object


def test_challenge_keeps_both_when_capability_collides():
    # two VULNERABLE verdicts for the same capability + a single refutation -> keep both
    from codejury.domain.context import AnalysisContext
    from codejury.domain.artifact import CodeArtifact
    from codejury.domain.capability import Capability
    from codejury.domain.observation import Concession
    from codejury.orchestrators.challenge import ChallengeOrchestrator

    class _Verifier:
        def run(self, ctx):
            return [Verdict(capability="input_validation.x", status="VULNERABLE"),
                    Verdict(capability="input_validation.x", status="VULNERABLE")]

    class _Refuter:
        def run(self, ctx):
            return [Concession(capability="input_validation.x", target="input_validation.x", reason="fp")]

    ctx = AnalysisContext(
        artifact=CodeArtifact(kind="file", path="a.py", content="x"),
        capabilities=[Capability(id="input_validation", name="iv")],
    )
    result = ChallengeOrchestrator().run({"verifier": _Verifier(), "refuter": _Refuter()}, ctx)
    vulns = [o for o in result.observations if o.kind == "verdict" and o.status == "VULNERABLE"]
    assert len(vulns) == 2  # ambiguous refutation did not drop either


def test_retry_exposes_public_inner():
    from codejury.providers.mock import MockProvider
    from codejury.providers.retry import RetryProvider
    inner = MockProvider()
    assert RetryProvider(inner).inner is inner


def test_function_source_skips_nested_functions():
    from codejury.sources.function import FunctionSource
    code = "def outer():\n    def inner():\n        pass\n    return inner\n"
    names = [a.path.split("::")[-1] for a in FunctionSource(code).list_artifacts()]
    assert names == ["outer"]  # inner is inside outer's artifact, not emitted again


def test_suppression_rejects_empty_match_any(tmp_path):
    from codejury.suppression import load_suppressions
    f = tmp_path / "s.yaml"
    f.write_text("- {id: noop, path_ext: ['.py']}\n")
    with pytest.raises(ValueError):
        load_suppressions(f)


def test_challenge_surfaces_verifier_error_not_traceback():
    # a provider failure in challenge must become AnalysisResult.error, not raise
    from codejury.domain.artifact import CodeArtifact
    from codejury.domain.capability import Capability
    from codejury.domain.context import AnalysisContext
    from codejury.orchestrators.challenge import ChallengeOrchestrator

    class _Boom:
        def run(self, ctx):
            raise RuntimeError("provider down")

    ctx = AnalysisContext(
        artifact=CodeArtifact(kind="file", path="a.py", content="x"),
        capabilities=[Capability(id="input_validation", name="iv")],
    )
    result = ChallengeOrchestrator().run({"verifier": _Boom(), "refuter": _Boom()}, ctx)
    assert result.error and "verifier" in result.error


def test_cache_get_tolerates_corrupt_entry(tmp_path):
    from codejury.infrastructure.cache import VerdictCache
    (tmp_path / "k.json").write_text("{ not valid json")
    assert VerdictCache(tmp_path).get("k") is None  # treated as a miss, not a crash

