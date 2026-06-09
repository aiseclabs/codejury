"""Severity calibration: the firm-rule floor lifts determinable classes to a known
minimum, the median damps grade jitter, and neither ever lowers a model's severity."""

from codejury.review.repo.severity import calibrated, floor_for, higher, median, normalize


def test_normalize_reads_the_level_from_free_text():
    assert normalize("HIGH") == "HIGH"
    assert normalize("critical risk") == "CRITICAL"
    assert normalize("") == "MEDIUM"
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
    assert floor_for("Information Exposure") is None
    assert floor_for("other") is None


def test_calibrated_raises_to_floor_but_never_lowers():
    assert calibrated("MEDIUM", "Hardcoded Secret / Credential Exposure") == "HIGH"
    assert calibrated("CRITICAL", "Missing Authorization / IDOR") == "CRITICAL"
    assert calibrated("LOW", "Information Exposure") == "LOW"
