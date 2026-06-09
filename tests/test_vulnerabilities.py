"""The rich vulnerability-class library loads, and trigger-based selection
picks the relevant classes for a diff to inject into the audit prompt."""

from codejury.review.diff.vulnerabilities import (
    Vulnerability,
    allowed_categories,
    load_vulnerabilities,
    normalize_category,
    select_vulnerabilities,
    vulnerabilities_for_diff,
)
from codejury.resources import KNOWLEDGE_INDEX, VULNERABILITIES_DIR

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

_VULNS = load_vulnerabilities()
_BY_ID = {v.id: v for v in _VULNS}

_SQL_DIFF = "+    cursor.execute('SELECT * FROM users WHERE n=' + name)\n"
_CMDI_DIFF = "+    os.system('ping ' + host)\n"


def test_vulnerabilities_are_exactly_the_frozen_set():
    assert set(_BY_ID) == _EXPECTED_IDS
    assert allowed_categories() == sorted(_EXPECTED_IDS)


def test_normalize_category_maps_onto_vulnerability_id_set():
    allowed = set(allowed_categories())
    assert normalize_category("sql_injection", allowed) == "sql-injection"   # underscore -> hyphen
    assert normalize_category("SQL Injection", allowed) == "sql-injection"   # case + space
    assert normalize_category("sql-injection", allowed) == "sql-injection"   # already canonical
    assert normalize_category("buffer overflow", allowed) == "other"         # not in the closed set
    assert normalize_category("", allowed) == ""                             # empty stays empty


def test_vulnerabilities_load_with_frontmatter():
    sqli = _BY_ID["sql-injection"]
    assert sqli.impact == "CRITICAL"
    assert "cwe-89" in sqli.tags
    assert sqli.triggers and "Parameterized" not in sqli.triggers  # triggers, not prose
    assert "parameterized queries" in sqli.body.lower()           # body carries the guidance
    assert _BY_ID["insecure-direct-object-reference"].impact == "HIGH"  # renamed from idor (B convention)


def test_shipped_vulnerabilities_are_well_formed():
    for v in _VULNS:
        assert v.impact in ("CRITICAL", "HIGH", "MEDIUM", "LOW"), v.id
        assert v.triggers, f"{v.id}: no triggers"
        assert v.body.strip(), f"{v.id}: empty body"


def test_select_matches_by_trigger():
    sel = select_vulnerabilities(_SQL_DIFF, _VULNS)
    assert "sql-injection" in [v.id for v in sel]
    assert "server-side-request-forgery" not in [v.id for v in sel]   # unrelated class not pulled in


def test_select_is_capped_and_severity_ordered():
    # a diff that trips many triggers
    busy = "os.system(x)\ncursor.execute(q)\nrequests.get(u)\npickle.loads(d)\nopen(p)\njwt.decode(t)\n"
    sel = select_vulnerabilities(busy, _VULNS, limit=3)
    assert len(sel) == 3
    impacts = [v.impact for v in sel]
    assert impacts == sorted(impacts, key=lambda i: {"CRITICAL": 0, "HIGH": 1}.get(i, 2))   # criticals first


def test_no_match_is_empty():
    assert select_vulnerabilities("x = 1 + 2\n", _VULNS) == []
    assert vulnerabilities_for_diff("x = 1 + 2\n") == ""


def test_vulnerabilities_for_diff_returns_relevant_body():
    text = vulnerabilities_for_diff(_CMDI_DIFF)
    assert "Command Injection" in text and "shell=False" in text
    assert "SQL Injection" not in text                  # only the matched class


def test_knowledge_index_ships_and_is_not_a_vulnerability():
    assert "index" not in {v.id for v in _VULNS}        # the index is not loaded as a class
    assert KNOWLEDGE_INDEX.is_file()                    # it ships beside vulnerabilities/, not inside it
    assert KNOWLEDGE_INDEX.parent == VULNERABILITIES_DIR.parent
