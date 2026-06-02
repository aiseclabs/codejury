"""R1: SkillRunner executes a skill's playbook against code via a provider and
parses verdicts. Defensive parsing; invariant 3 (a problem needs a location)
enforced at parse time."""

import json

from codejury.agents.skill_runner import SkillRunner
from codejury.domain.artifact import CodeArtifact
from codejury.domain.context import AnalysisContext
from codejury.domain.skill import Skill
from codejury.providers.mock import MockProvider

SQLI = Skill(id="sql_injection", name="SQL Injection", cwe="CWE-89", instructions="Flag concatenated queries.")
XSS = Skill(id="xss", name="XSS", instructions="Flag unescaped output.")


def _ctx(skills, *, content="q = 'SELECT ' + user", context=""):
    return AnalysisContext(
        artifact=CodeArtifact(kind="api_endpoint", path="app.py::view", content=content, context=context),
        skills=skills,
    )


def _verdict(status, *, dimension="", evidence=None, cwe="", confidence=0.9):
    v = {"dimension": dimension, "status": status, "reasoning": "r", "confidence": confidence, "cwe": cwe}
    if evidence is not None:
        v["evidence"] = evidence
    return json.dumps({"verdicts": [v]})


def _run(skills, response):
    provider = MockProvider(default=response)
    out = SkillRunner(provider=provider, model="m").run(_ctx(skills))
    return provider, out


def test_parses_a_verdict_from_the_playbook_reply():
    ev = [{"file": "app.py", "line": 3, "code": "q = ..."}]
    _, out = _run([SQLI], _verdict("VULNERABLE", dimension="query", evidence=ev))
    assert len(out) == 1
    v = out[0]
    assert v.capability == "sql_injection.query"
    assert v.produced_by == "skill"
    assert v.status == "VULNERABLE"
    assert v.cwe == "CWE-89"
    assert v.evidence[0].line == 3
    assert v.confidence == 0.9


def test_capability_is_skill_id_when_no_dimension():
    ev = [{"file": "app.py", "line": 1, "code": "x"}]
    _, out = _run([SQLI], _verdict("VULNERABLE", evidence=ev))
    assert out[0].capability == "sql_injection"


def test_one_provider_call_per_skill():
    provider = MockProvider(default=_verdict("SECURE"))
    out = SkillRunner(provider=provider, model="m").run(_ctx([SQLI, XSS]))
    assert len(provider.calls) == 2
    assert len(out) == 2  # both SECURE verdicts kept


def test_problem_without_location_is_dropped():
    # VULNERABLE but no evidence at all: invariant 3 -> not reportable
    _, out = _run([SQLI], _verdict("VULNERABLE"))
    assert out == []


def test_problem_with_lineless_evidence_is_dropped():
    ev = [{"file": "app.py", "code": "x"}]  # no line
    _, out = _run([SQLI], _verdict("PARTIAL", evidence=ev))
    assert out == []


def test_secure_without_location_is_kept():
    _, out = _run([SQLI], _verdict("SECURE"))
    assert len(out) == 1 and out[0].status == "SECURE"


def test_cwe_falls_back_to_skill_when_model_omits():
    ev = [{"file": "app.py", "line": 2, "code": "x"}]
    _, out = _run([SQLI], _verdict("VULNERABLE", evidence=ev, cwe=""))
    assert out[0].cwe == "CWE-89"  # from the skill manifest


def test_model_cwe_overrides_skill_default():
    ev = [{"file": "app.py", "line": 2, "code": "x"}]
    _, out = _run([SQLI], _verdict("VULNERABLE", evidence=ev, cwe="CWE-564"))
    assert out[0].cwe == "CWE-564"


def test_unknown_status_falls_back_to_unknown():
    _, out = _run([SQLI], _verdict("EXPLODED"))
    assert out[0].status == "UNKNOWN"


def test_malformed_reply_yields_no_verdicts_not_an_error():
    _, out = _run([SQLI], "not json at all")
    assert out == []


def test_no_skills_means_no_calls():
    provider = MockProvider(default=_verdict("SECURE"))
    out = SkillRunner(provider=provider, model="m").run(_ctx([]))
    assert out == [] and provider.calls == []


def test_skill_instructions_reach_the_prompt():
    provider = MockProvider(default=_verdict("SECURE"))
    SkillRunner(provider=provider, model="m").run(_ctx([SQLI]))
    prompt = provider.calls[0]["messages"][0].content
    assert "Flag concatenated queries." in prompt
    assert "sql_injection" in prompt
