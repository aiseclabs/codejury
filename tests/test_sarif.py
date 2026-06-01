import json
from pathlib import Path

import jsonschema
import pytest

from codejury.domain.observation import Concession, Evidence, Finding, Verdict
from codejury.domain.result import AnalysisResult
from codejury.reporting import to_sarif

_SCHEMA = json.loads((Path(__file__).parent / "data" / "sarif-schema-2.1.0.json").read_text())


def _validate(sarif_text):
    doc = json.loads(sarif_text)
    jsonschema.validate(doc, _SCHEMA)  # raises if non-compliant
    return doc


def _sample_results():
    return [
        (
            "auth.py",
            AnalysisResult(
                observations=[
                    Verdict(
                        capability="authn.password_storage",
                        status="VULNERABLE",
                        reasoning="sha256 used for passwords",
                        cwe="CWE-916",
                        matched_anti=["fast_hash"],
                        evidence=[Evidence(file="auth.py", line=10, end_line=10, code="sha256(p)")],
                    ),
                    # cleared verdict: not a problem, must not appear as a result
                    Verdict(
                        capability="authn.password_storage",
                        status="SECURE",
                        evidence=[Evidence(file="auth.py", line=12)],
                    ),
                    Finding(
                        capability="input_validation",
                        title="SQL injection",
                        description="query built by string concat",
                        severity="CRITICAL",
                        cwe="CWE-89",
                        evidence=[Evidence(file="auth.py", line=20, code="execute(q)")],
                    ),
                    # a problem with no location: invariant 3 says not reportable
                    Finding(capability="misc", title="no-location finding", severity="HIGH", cwe="CWE-1"),
                    # a concession is not a finding
                    Concession(capability="authn", target="SQL injection", reason="duplicate"),
                ]
            ),
        )
    ]


# --- acceptance (1): output validates against the official SARIF schema -------

def test_sarif_validates_against_official_schema():
    _validate(to_sarif(_sample_results()))


def test_empty_results_is_valid_sarif():
    doc = _validate(to_sarif([]))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []


# --- acceptance (2): every result has capability, CWE, and a precise location -

def test_every_result_carries_capability_cwe_and_location():
    doc = _validate(to_sarif(_sample_results()))
    results = doc["runs"][0]["results"]
    assert len(results) == 2  # VULNERABLE verdict + CRITICAL finding only

    for r in results:
        assert r["ruleId"]                              # capability id
        assert r["properties"]["capability"]
        assert r["properties"]["cwe"]                   # CWE present and non-empty
        region = r["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1                 # precise location
        assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "auth.py"


def test_rules_are_registered_and_indexed():
    doc = _validate(to_sarif(_sample_results()))
    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    rule_ids = [rule["id"] for rule in rules]
    assert rule_ids == ["authn.password_storage", "input_validation"]
    for r in run["results"]:
        assert rules[r["ruleIndex"]]["id"] == r["ruleId"]


# --- level mapping ------------------------------------------------------------

@pytest.mark.parametrize(
    "observation,expected",
    [
        (Verdict(capability="a.b", status="VULNERABLE", cwe="CWE-1",
                 evidence=[Evidence(file="f.py", line=1)]), "error"),
        (Verdict(capability="a.b", status="PARTIAL", cwe="CWE-1",
                 evidence=[Evidence(file="f.py", line=1)]), "warning"),
        (Finding(capability="a", title="t", severity="CRITICAL", cwe="CWE-1",
                 evidence=[Evidence(file="f.py", line=1)]), "error"),
        (Finding(capability="a", title="t", severity="MEDIUM", cwe="CWE-1",
                 evidence=[Evidence(file="f.py", line=1)]), "warning"),
        (Finding(capability="a", title="t", severity="LOW", cwe="CWE-1",
                 evidence=[Evidence(file="f.py", line=1)]), "note"),
    ],
)
def test_level_mapping(observation, expected):
    doc = _validate(to_sarif([("f.py", AnalysisResult(observations=[observation]))]))
    assert doc["runs"][0]["results"][0]["level"] == expected
