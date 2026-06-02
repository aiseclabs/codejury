"""RW-3: the rich rule library loads, and trigger-based selection picks the
on-topic rules for a diff to inject into the audit prompt."""

from codejury.diff.rules import Rule, allowed_categories, load_rules, rules_for_diff, select_rules
from codejury.resources import RULES_DIR

# The frozen 25-class application-security set (id = category = SARIF ruleId).
_EXPECTED_IDS = {
    "missing-authorization", "insecure-direct-object-reference", "cross-site-request-forgery",
    "path-traversal", "open-redirect", "insecure-cryptography", "insecure-transport",
    "hardcoded-secrets", "information-exposure", "sql-injection", "command-injection",
    "code-injection", "cross-site-scripting", "xml-external-entity",
    "server-side-template-injection", "http-response-splitting", "business-logic",
    "replay-attack", "race-condition", "mass-assignment", "improper-authentication",
    "jwt-validation", "session-fixation", "insecure-deserialization",
    "server-side-request-forgery",
}

_RULES = load_rules()
_BY_ID = {r.id: r for r in _RULES}

_SQL_DIFF = "+    cursor.execute('SELECT * FROM users WHERE n=' + name)\n"
_CMDI_DIFF = "+    os.system('ping ' + host)\n"


def test_rules_are_exactly_the_frozen_set():
    assert set(_BY_ID) == _EXPECTED_IDS
    assert allowed_categories() == sorted(_EXPECTED_IDS)


def test_rules_load_with_frontmatter():
    sqli = _BY_ID["sql-injection"]
    assert sqli.impact == "CRITICAL"
    assert "cwe-89" in sqli.tags
    assert sqli.triggers and "Parameterized" not in sqli.triggers  # triggers, not prose
    assert "parameterized queries" in sqli.body.lower()           # body carries the guidance
    assert _BY_ID["insecure-direct-object-reference"].impact == "HIGH"  # renamed from idor (B convention)


def test_shipped_rules_are_well_formed():
    for r in _RULES:
        assert r.impact in ("CRITICAL", "HIGH", "MEDIUM", "LOW"), r.id
        assert r.triggers, f"{r.id}: no triggers"
        assert r.body.strip(), f"{r.id}: empty body"


def test_select_matches_by_trigger():
    sel = select_rules(_SQL_DIFF, _RULES)
    assert "sql-injection" in [r.id for r in sel]
    assert "server-side-request-forgery" not in [r.id for r in sel]   # unrelated rule not pulled in


def test_select_is_capped_and_severity_ordered():
    # a diff that trips many triggers
    busy = "os.system(x); cursor.execute(q); requests.get(u); pickle.loads(d); open(p); jwt.decode(t)\n"
    sel = select_rules(busy, _RULES, limit=3)
    assert len(sel) == 3
    impacts = [r.impact for r in sel]
    assert impacts == sorted(impacts, key=lambda i: {"CRITICAL": 0, "HIGH": 1}.get(i, 2))  # criticals first


def test_no_match_is_empty():
    assert select_rules("x = 1 + 2\n", _RULES) == []
    assert rules_for_diff("x = 1 + 2\n") == ""


def test_rules_for_diff_returns_relevant_body():
    text = rules_for_diff(_CMDI_DIFF)
    assert "Command Injection" in text and "shell=False" in text
    assert "SQL Injection" not in text                  # only the matched rule


def test_skill_index_is_not_loaded_as_a_rule():
    assert "SKILL" not in {r.id for r in _RULES}
    assert (RULES_DIR / "SKILL.md").is_file()           # but the agent index ships
