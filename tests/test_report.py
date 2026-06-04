"""RW-5: render Findings as text/markdown/json/sarif and gate on severity."""

import json
from pathlib import Path

import jsonschema

from codejury.report import (
    gate,
    render,
    severity_breakdown,
    to_json,
    to_sarif,
)
from codejury.finding import Finding

_SCHEMA = json.loads((Path(__file__).parent / "data" / "sarif-schema-2.1.0.json").read_text())

_FINDINGS = [
    Finding(file="app/payment.py", line=42, severity="CRITICAL", category="sql_injection",
            description="string-concatenated query", exploit_scenario="send ' OR 1=1 --", confidence=0.95),
    Finding(file="app/views.py", line=10, severity="MEDIUM", category="idor",
            description="missing ownership check", confidence=0.6),
]


def test_breakdown_and_sort():
    assert severity_breakdown(_FINDINGS) == {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 1, "LOW": 0}


def test_text_lists_severity_and_location():
    out = render("text", _FINDINGS)
    assert "[CRITICAL] sql_injection app/payment.py:42" in out
    assert "exploit:" in out


def test_markdown_has_summary_and_sections():
    out = render("markdown", _FINDINGS)
    assert "1 critical, 0 high, 1 medium" in out
    assert "`app/payment.py:42`" in out


def test_json_shape():
    doc = json.loads(to_json(_FINDINGS))
    assert set(doc) == {"findings", "summary"}
    assert doc["findings"][0]["severity"] == "CRITICAL"  # sorted, critical first


def test_sarif_validates_against_schema():
    doc = json.loads(to_sarif(_FINDINGS))
    jsonschema.validate(doc, _SCHEMA)
    res = doc["runs"][0]["results"]
    assert res[0]["ruleId"] == "sql_injection" and res[0]["level"] == "error"
    assert res[0]["properties"]["confidence"] == 0.95


def test_empty_render():
    assert render("text", []) == "no findings"
    jsonschema.validate(json.loads(to_sarif([])), _SCHEMA)


def test_gate():
    assert gate(_FINDINGS, "high") is True       # a CRITICAL clears the high gate
    assert gate(_FINDINGS, "critical") is True
    assert gate([_FINDINGS[1]], "high") is False  # only a MEDIUM left
    assert gate(_FINDINGS, None) is False
