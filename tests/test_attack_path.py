"""P6-03: suspected attack-path synthesis and its serialization / SARIF mapping.

Paths are stitched from the taint vocabulary and the finding's evidence, anchored
to real lines, and marked suspected (not proven)."""

import json
from pathlib import Path

import jsonschema

from codejury.analysis.attack_path import attach_suspected_paths, suspected_path
from codejury.domain.artifact import CodeArtifact
from codejury.domain.observation import (
    Evidence,
    Finding,
    PathStep,
    Verdict,
    observation_from_dict,
)
from codejury.domain.result import AnalysisResult
from codejury.reporting import to_sarif

_SCHEMA = json.loads((Path(__file__).parent / "data" / "sarif-schema-2.1.0.json").read_text())

# The cross-file golden shape: a param-only sink, the source in the caller.
_SINK = "def serve(name):\n    return open(os.path.join(STATIC_DIR, name)).read()\n"
_CALLER = "def download(request):\n    return serve(request.args['name'])\n"


# --- domain: round-trip through JSON (cache / baseline) ---

def test_pathstep_round_trips_through_to_dict():
    v = Verdict(
        capability="input_validation.path_traversal",
        status="VULNERABLE",
        evidence=[Evidence(file="s.py", line=2)],
        attack_path=[
            PathStep(file="<context>", line=2, role="source", note="request.args"),
            PathStep(file="s.py", line=2, role="sink", note="open"),
        ],
    )
    back = observation_from_dict(v.to_dict())
    assert back == v
    assert back.attack_path[0].role == "source" and back.attack_path[1].role == "sink"
    assert back.attack_path_proven is False


def test_default_observation_has_no_path():
    assert Finding(title="x").attack_path == []
    assert Verdict(capability="c", status="VULNERABLE").attack_path == []


# --- synthesis ---

def test_local_source_to_sink_path():
    content = "def f(request):\n    return open(request.args['p']).read()\n"
    steps = suspected_path(content=content, sink_file="f.py", sink_line=2, sink_note="path_traversal")
    assert [s.role for s in steps] == ["source", "sink"]
    assert steps[0].file == "f.py" and steps[0].line == 2  # request.args is on line 2
    assert steps[1].line == 2


def test_cross_file_source_in_caller():
    steps = suspected_path(content=_SINK, context=_CALLER, sink_file="sink.py", sink_line=2)
    assert [s.role for s in steps] == ["source", "sink"]
    assert steps[0].file == "<context>" and steps[0].line == 2  # source is in the caller
    assert steps[1].file == "sink.py" and steps[1].line == 2    # sink in the reviewed file


def test_no_external_source_yields_no_path():
    # a hardcoded secret has no source -> sink data flow; no path fabricated
    content = 'API_KEY = "sk_live_secret"\n'
    assert suspected_path(content=content, sink_file="c.py", sink_line=1) == []


def test_sink_without_line_yields_no_path():
    content = "def f(request):\n    return open(request.args['p'])\n"
    assert suspected_path(content=content, sink_file="f.py", sink_line=None) == []


# --- enrichment of a result ---

def test_attach_adds_path_to_taint_finding_with_evidence():
    artifact = CodeArtifact(kind="file", path="sink.py", content=_SINK, context=_CALLER)
    result = AnalysisResult(observations=[
        Verdict(capability="input_validation.path_traversal", status="VULNERABLE",
                evidence=[Evidence(file="sink.py", line=2, code="open(...)")]),
    ])
    enriched = attach_suspected_paths(result, artifact)
    path = enriched.observations[0].attack_path
    assert [s.role for s in path] == ["source", "sink"]
    assert enriched.observations[0].attack_path_proven is False


def test_attach_leaves_non_taint_and_secure_alone():
    artifact = CodeArtifact(kind="file", path="c.py", content='KEY = "sk_secret"\n')
    result = AnalysisResult(observations=[
        Finding(capability="secrets.storage", title="hardcoded key",
                evidence=[Evidence(file="c.py", line=1)]),                 # no source -> no path
        Verdict(capability="authn.x", status="SECURE",
                evidence=[Evidence(file="c.py", line=1)]),                 # not a problem
    ])
    enriched = attach_suspected_paths(result, artifact)
    assert all(o.attack_path == [] for o in enriched.observations)
    assert enriched is result  # unchanged -> same object


# --- SARIF codeFlows (acceptance 2) ---

def _validate(text):
    doc = json.loads(text)
    jsonschema.validate(doc, _SCHEMA)
    return doc


def test_sarif_emits_codeflows_for_an_attack_path_and_validates():
    result = AnalysisResult(observations=[
        Verdict(
            capability="input_validation.path_traversal", status="VULNERABLE", cwe="CWE-22",
            evidence=[Evidence(file="sink.py", line=2, code="open(...)")],
            attack_path=[
                PathStep(file="<context>", line=2, role="source", note="request.args"),
                PathStep(file="sink.py", line=2, role="sink", note="open"),
            ],
        )
    ])
    doc = _validate(to_sarif([("sink.py", result)]))
    res = doc["runs"][0]["results"][0]
    flows = res["codeFlows"]
    locs = flows[0]["threadFlows"][0]["locations"]
    assert [l["location"]["message"]["text"].split(":")[0] for l in locs] == ["source", "sink"]
    assert res["properties"]["attackPathProven"] is False


def test_sarif_without_path_has_no_codeflows():
    result = AnalysisResult(observations=[
        Finding(capability="secrets.storage", title="key", severity="HIGH", cwe="CWE-798",
                evidence=[Evidence(file="c.py", line=1)]),
    ])
    doc = _validate(to_sarif([("c.py", result)]))
    assert "codeFlows" not in doc["runs"][0]["results"][0]
