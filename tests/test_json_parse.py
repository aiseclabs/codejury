import pytest

from codejury.json_parse import extract_json_object


def test_direct_object():
    assert extract_json_object('{"a": 1}') == {"a": 1}


def test_fenced_block():
    text = 'here you go:\n```json\n{"a": 1, "b": [2, 3]}\n```\nthanks'
    assert extract_json_object(text) == {"a": 1, "b": [2, 3]}


def test_object_amid_prose():
    text = 'The verdict is {"status": "SECURE"} as shown.'
    assert extract_json_object(text) == {"status": "SECURE"}


def test_nested_braces():
    text = 'noise {"outer": {"inner": {"x": 1}}} trailing'
    assert extract_json_object(text) == {"outer": {"inner": {"x": 1}}}


@pytest.mark.parametrize("text", ["", "no json here", "{not valid}", "[1, 2, 3]"])
def test_no_object_returns_none(text):
    assert extract_json_object(text) is None


def test_braces_inside_string_value_do_not_corrupt_depth():
    text = '{"description": "the sink is cursor.execute({user})", "line": 7}'
    assert extract_json_object(text) == {"description": "the sink is cursor.execute({user})", "line": 7}


def test_trailing_comma_is_repaired():
    assert extract_json_object('{"a": 1, "b": 2,}') == {"a": 1, "b": 2}


def test_truncated_object_is_repaired():
    out = extract_json_object('{"findings": [{"file": "a.py", "description": "unterminated')
    assert isinstance(out, dict) and "findings" in out
