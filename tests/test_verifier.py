import json
from pathlib import Path

from codejury.agents.verifier import VerifierAgent
from codejury.domain.artifact import CodeArtifact
from codejury.domain.capability import load_capability
from codejury.domain.context import AnalysisContext
from codejury.providers.mock import MockProvider

CAPABILITIES_DIR = Path(__file__).resolve().parent.parent / "capabilities"


def _ctx(content="+ hashlib.sha256(pwd)"):
    cap = load_capability(CAPABILITIES_DIR / "authentication.yaml")
    artifact = CodeArtifact(kind="diff", path="auth.py", content=content)
    return AnalysisContext(artifact=artifact, capabilities=[cap])


def test_parses_verdicts_from_canned_reply():
    reply = json.dumps(
        {
            "verdicts": [
                {
                    "sub_capability": "password_storage",
                    "status": "VULNERABLE",
                    "reasoning": "sha256 used for password hashing",
                    "matched_anti": ["PWD-BAD-1"],
                    "evidence": [{"file": "auth.py", "line": 1, "code": "hashlib.sha256(pwd)"}],
                    "confidence": 0.9,
                },
                {"sub_capability": "jwt_verification", "status": "NOT_PRESENT"},
            ]
        }
    )
    agent = VerifierAgent(provider=MockProvider(default=reply), model="mock")
    verdicts = agent.run(_ctx())

    assert [v.capability for v in verdicts] == ["authn.password_storage", "authn.jwt_verification"]
    vuln = verdicts[0]
    assert vuln.status == "VULNERABLE"
    assert vuln.matched_anti == ["PWD-BAD-1"]
    assert vuln.evidence[0].line == 1
    assert vuln.confidence == 0.9
    assert verdicts[1].status == "NOT_PRESENT"


def test_prompt_includes_patterns_and_code():
    captured = MockProvider(default='{"verdicts": []}')
    VerifierAgent(provider=captured, model="mock").run(_ctx(content="UNIQUE_MARKER"))
    prompt = captured.calls[0]["messages"][0].content
    assert "PWD-BAD-1" in prompt          # anti pattern rendered
    assert "password_storage" in prompt   # sub_capability listed
    assert "UNIQUE_MARKER" in prompt       # code under review embedded


def test_malformed_reply_yields_no_verdicts():
    agent = VerifierAgent(provider=MockProvider(default="sorry, I cannot help"), model="mock")
    assert agent.run(_ctx()) == []


def test_unknown_status_falls_back():
    reply = '{"verdicts": [{"sub_capability": "password_storage", "status": "BANANA"}]}'
    agent = VerifierAgent(provider=MockProvider(default=reply), model="mock")
    assert agent.run(_ctx())[0].status == "UNKNOWN"
