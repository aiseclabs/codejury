"""R0: the Skill data format and loader. A skill is a reviewable data directory
(skill.yaml manifest + SKILL.md playbook); the loader is deterministic and holds
no audit logic."""

import pytest

from codejury.domain.skill import Skill, load_skill, load_skills
from codejury.resources import SKILLS_DIR

MANIFEST = """\
id: sql_injection
name: SQL Injection
version: "1"
applies_to: [api_endpoint, diff]
standard: OWASP ASVS V5
cwe: CWE-89
severity: HIGH
tags: [database, query]
"""

PLAYBOOK = "# SQL Injection\n\nFlag queries built by string concatenation of untrusted input.\n"


def _write_skill(root, sid, *, manifest=MANIFEST, playbook=PLAYBOOK):
    d = root / sid
    d.mkdir()
    (d / "skill.yaml").write_text(manifest)
    if playbook is not None:
        (d / "SKILL.md").write_text(playbook)
    return d


def test_loads_manifest_and_playbook(tmp_path):
    skill = load_skill(_write_skill(tmp_path, "sql_injection"))
    assert skill.id == "sql_injection"
    assert skill.name == "SQL Injection"
    assert skill.version == "1"
    assert skill.applies_to == ("api_endpoint", "diff")
    assert skill.standard == "OWASP ASVS V5"
    assert skill.cwe == "CWE-89"
    assert skill.severity == "HIGH"
    assert skill.tags == ("database", "query")
    assert "string concatenation" in skill.instructions


def test_defaults_when_optional_fields_absent(tmp_path):
    minimal = 'id: x\nname: X\n'
    skill = load_skill(_write_skill(tmp_path, "x", manifest=minimal))
    assert skill.version == "0"
    assert skill.applies_to == ()
    assert skill.tags == ()
    assert skill.severity == "MEDIUM"
    assert skill.cwe == ""


def test_unknown_manifest_keys_are_ignored(tmp_path):
    m = MANIFEST + "future_field: whatever\n"
    skill = load_skill(_write_skill(tmp_path, "sql_injection", manifest=m))
    assert skill.id == "sql_injection"


def test_missing_playbook_is_an_error(tmp_path):
    with pytest.raises(ValueError, match="needs a playbook"):
        load_skill(_write_skill(tmp_path, "nopb", playbook=None))


def test_missing_manifest_is_an_error(tmp_path):
    d = tmp_path / "only_playbook"
    d.mkdir()
    (d / "SKILL.md").write_text(PLAYBOOK)
    with pytest.raises(ValueError, match="missing skill.yaml"):
        load_skill(d)


def test_missing_required_key_is_an_error(tmp_path):
    with pytest.raises(ValueError, match="missing required key"):
        load_skill(_write_skill(tmp_path, "noid", manifest='name: No Id\n'))


def test_invalid_severity_is_an_error(tmp_path):
    bad = 'id: x\nname: X\nseverity: SCARY\n'
    with pytest.raises(ValueError, match="invalid severity"):
        load_skill(_write_skill(tmp_path, "x", manifest=bad))


def test_load_skills_sorted_and_skips_non_skill_dirs(tmp_path):
    _write_skill(tmp_path, "bbb")
    _write_skill(tmp_path, "aaa")
    (tmp_path / "not_a_skill").mkdir()  # no skill.yaml, ignored
    skills = load_skills(tmp_path)
    assert [s.id for s in skills] == ["sql_injection", "sql_injection"]  # both manifests share id
    assert len(skills) == 2


def test_load_skills_missing_dir_is_empty(tmp_path):
    assert load_skills(tmp_path / "does_not_exist") == []


def test_fingerprint_is_deterministic_and_content_sensitive(tmp_path):
    a = load_skill(_write_skill(tmp_path, "a", manifest=MANIFEST))
    b_root = tmp_path / "b_parent"
    b_root.mkdir()
    b = load_skill(_write_skill(b_root, "a", manifest=MANIFEST))  # identical content
    assert a.fingerprint() == b.fingerprint()

    bumped = load_skill(_write_skill(tmp_path, "c", manifest=MANIFEST.replace('version: "1"', 'version: "2"')))
    assert bumped.fingerprint() != a.fingerprint()

    edited = load_skill(_write_skill(tmp_path, "d", playbook=PLAYBOOK + "\nAlso flag f-string queries.\n"))
    assert edited.fingerprint() != a.fingerprint()


def test_skill_is_frozen_and_hashable():
    s = Skill(id="x", name="X")
    assert s in {s}
    with pytest.raises(Exception):
        s.id = "y"  # frozen


# --- shipped skills (the migrated security knowledge base) ---

_EXPECTED_SKILLS = {
    "api_design", "authn", "authz", "business_logic", "crypto", "data_protection",
    "dependency_config", "error_logging", "excessive_agency", "input_validation",
    "insecure_output_handling", "model_supply_chain", "output_encoding",
    "prompt_injection", "secrets", "session",
}
# 15 migrated skills + api_design (rescoped to cross-endpoint authz, cors, mass
# assignment). architecture stays down pending golden; the full-review design
# stage resumes when a signed design skill ships.


def test_shipped_skills_are_the_full_set():
    assert {s.id for s in load_skills(SKILLS_DIR)} == _EXPECTED_SKILLS


def test_shipped_skills_carry_a_playbook_and_valid_metadata():
    for s in load_skills(SKILLS_DIR):
        assert s.instructions.strip(), f"{s.id}: empty playbook"
        assert s.cwe.startswith("CWE-"), f"{s.id}: missing CWE fallback"
        assert s.standard, f"{s.id}: missing standard reference"
