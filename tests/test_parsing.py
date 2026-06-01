import math

from codejury.agents.parsing import one_of, str_list, to_evidence, to_float


def test_one_of_rejects_unhashable_without_raising():
    # a model returning a list/dict for an enum field must fall back, not crash
    assert one_of([], {"A", "B"}, "A") == "A"
    assert one_of({}, {"A", "B"}, "A") == "A"
    assert one_of("B", {"A", "B"}, "A") == "B"
    assert one_of("Z", {"A", "B"}, "A") == "A"


def test_to_float_rejects_nan_inf_and_bool():
    assert to_float(float("nan"), 0.5) == 0.5
    assert to_float(float("inf"), 0.5) == 0.5
    assert to_float(True, 0.5) == 0.5          # bool is an int subclass; reject it
    assert to_float("0.9", 0.5) == 0.9
    assert to_float(0.3, 0.5) == 0.3
    assert math.isfinite(to_float("oops", 0.5))


def test_to_evidence_requires_positive_int_line():
    assert to_evidence([{"file": "a.py", "line": 0}])[0].line is None
    assert to_evidence([{"file": "a.py", "line": -3}])[0].line is None
    assert to_evidence([{"file": "a.py", "line": True}])[0].line is None  # bool rejected
    assert to_evidence([{"file": "a.py", "line": 5}])[0].line == 5


def test_str_list_tolerates_non_list():
    assert str_list("x") == []
    assert str_list(["a", 1]) == ["a", "1"]
