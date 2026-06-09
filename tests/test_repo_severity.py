"""Severity calibration: the firm-rule floor lifts determinable classes to a known
minimum, the median damps grade jitter, and neither ever lowers a model's severity."""

from codejury.review.repo.severity import calibrated, floor_for, higher, median, normalize


def test_normalize_reads_the_level_from_free_text():
    assert normalize("HIGH") == "HIGH"
    assert normalize("critical risk") == "CRITICAL"
    assert normalize("") == "MEDIUM"            # default when unstated
    assert normalize("nonsense") == "MEDIUM"


def test_higher_never_picks_the_lower_level():
    assert higher("LOW", "HIGH") == "HIGH"
    assert higher("CRITICAL", "MEDIUM") == "CRITICAL"


def test_median_damps_jitter_to_the_middle_grade():
    assert median(["LOW", "HIGH", "MEDIUM"]) == "MEDIUM"
    assert median(["CRITICAL", "CRITICAL", "MEDIUM"]) == "CRITICAL"
    assert median([]) == "MEDIUM"


def test_floor_for_the_firm_rules():
    assert floor_for("Credential / Secret Exposure") == "HIGH"
    assert floor_for("Replay Attack / Missing Freshness Window") == "HIGH"
    assert floor_for("Broken Authentication / JWT Forgery") == "HIGH"
    assert floor_for("Missing Authorization / IDOR") == "MEDIUM"
    assert floor_for("Information Exposure") is None      # not a firm-rule class
    assert floor_for("other") is None


def test_calibrated_raises_to_floor_but_never_lowers():
    # a credential leak the model under-graded MEDIUM is lifted to the HIGH floor
    assert calibrated("MEDIUM", "Hardcoded Secret / Credential Exposure") == "HIGH"
    # a model-graded CRITICAL on an IDOR (MEDIUM floor) stays CRITICAL, floor never lowers
    assert calibrated("CRITICAL", "Missing Authorization / IDOR") == "CRITICAL"
    # no firm rule: the model's grade stands
    assert calibrated("LOW", "Information Exposure") == "LOW"
