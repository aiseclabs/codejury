from codejury.domain.observation import Concession, Finding, Verdict
from codejury.domain.result import AnalysisResult
from codejury.resources import SUPPRESSIONS_FILE
from codejury.suppression import Suppression, filter_results, load_suppressions


def test_matches_keyword_and_path_conditions():
    rule = Suppression(id="R", match_any=("rate limit",))
    assert rule.matches(Finding(title="Missing rate limit on endpoint"), "x.py")
    assert not rule.matches(Finding(title="SQL injection"), "x.py")

    mem = Suppression(id="M", match_any=("buffer overflow",), unless_path_ext=(".c",))
    assert mem.matches(Finding(title="buffer overflow"), "x.py")        # python -> applies
    assert not mem.matches(Finding(title="buffer overflow"), "x.c")     # C -> skipped
    assert not mem.matches(Finding(title="buffer overflow"), "x.c#2")   # chunk suffix handled


def test_filter_drops_problems_keeps_clean_and_non_problems():
    rules = [Suppression(id="R", match_any=("rate limit",), reason="noise")]
    obs = [
        Finding(title="Missing rate limit"),                       # suppressed
        Finding(title="Hardcoded API key"),                        # kept (no match)
        Verdict(capability="authn", status="SECURE", reasoning="rate limit fine"),  # kept (not a problem)
        Verdict(capability="input_validation.x", status="VULNERABLE", reasoning="rate limit missing"),  # suppressed
        Concession(target="x", reason="rate limit"),               # kept (not a problem)
    ]
    results = [("f.py", AnalysisResult(observations=obs))]
    filtered, suppressed = filter_results(results, rules)

    kept_titles = [getattr(o, "title", o.capability) for o in filtered[0][1].observations]
    assert "Missing rate limit" not in kept_titles
    assert "Hardcoded API key" in kept_titles
    assert len(suppressed) == 2  # the Finding + the VULNERABLE verdict
    assert {s[2] for s in suppressed} == {"R"}
    # SECURE verdict and concession survive
    assert any(o.kind == "verdict" and o.status == "SECURE" for o in filtered[0][1].observations)
    assert any(o.kind == "concession" for o in filtered[0][1].observations)


def test_shipped_suppressions_load_and_cover_availability():
    rules = load_suppressions(SUPPRESSIONS_FILE)
    assert any(r.id == "SUP-AVAILABILITY" for r in rules)
    dos = next(r for r in rules if r.id == "SUP-AVAILABILITY")
    assert dos.matches(Finding(title="Potential Denial of Service via unbounded loop"), "x.py")
