from pathlib import Path

import pytest

from codejury.domain.capability import (
    AntiPattern,
    Capability,
    SubCapability,
    load_capabilities,
    load_capability,
)

CAPABILITIES_DIR = Path(__file__).resolve().parent.parent / "capabilities"


@pytest.mark.parametrize("path", sorted(CAPABILITIES_DIR.glob("*.yaml")), ids=lambda p: p.stem)
def test_shipped_capabilities_load(path):
    """Every shipped capability file parses into a well-formed Capability.

    This is the regression guard against a malformed YAML slipping in.
    """
    cap = load_capability(path)
    assert cap.id and cap.name
    assert cap.sub_capabilities
    for sub in cap.sub_capabilities.values():
        assert isinstance(sub, SubCapability)


def test_load_capabilities_loads_every_file():
    caps = load_capabilities(CAPABILITIES_DIR)
    ids = {c.id for c in caps}
    assert {"authn", "input_validation"} <= ids


def test_authentication_structure():
    cap = load_capability(CAPABILITIES_DIR / "authentication.yaml")
    assert cap.id == "authn"
    pwd = cap.sub_capabilities["password_storage"]
    assert [p.id for p in pwd.correct_patterns] == ["PWD-OK-1"]
    first_anti = pwd.anti_patterns[0]
    assert first_anti.cwe == "CWE-916"
    assert first_anti.severity == "HIGH"
    assert "bcrypt" in first_anti.example_good


def test_from_dict_ignores_unknown_keys():
    cap = Capability.from_dict(
        {
            "id": "x",
            "name": "X",
            "future_field": 1,
            "sub_capabilities": {"s": {"future": 2, "anti_patterns": [{"id": "A", "extra": 9}]}},
        }
    )
    assert cap.id == "x"
    assert cap.sub_capabilities["s"].anti_patterns[0].id == "A"


@pytest.mark.parametrize("data", [{"name": "X"}, {"id": "x"}])
def test_from_dict_requires_id_and_name(data):
    with pytest.raises(KeyError):
        Capability.from_dict(data)


def test_anti_pattern_defaults():
    ap = AntiPattern.from_dict({"id": "A"})
    assert ap.severity == "MEDIUM"
    assert ap.signals == []
    assert ap.cwe == ""


def test_load_rejects_non_mapping(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_capability(bad)


def test_capability_is_frozen():
    cap = Capability.from_dict({"id": "x", "name": "X"})
    with pytest.raises(Exception):
        cap.id = "y"
