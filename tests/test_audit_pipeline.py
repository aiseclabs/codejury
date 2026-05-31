"""End-to-end proof of audit_diff_single: real capability data drives a verdict.

Wires the real authentication.yaml + a diff carrying the sha256 anti-pattern
through VerifierAgent and SingleOrchestrator, with MockProvider standing in for
the model. Swapping in a real provider (Phase 1) is the only change needed to
run this against a live PR.
"""

import json

from codejury.agents.verifier import VerifierAgent
from codejury.domain.artifact import CodeArtifact
from codejury.domain.capability import load_capability
from codejury.domain.context import AnalysisContext
from codejury.orchestrators.single import SingleOrchestrator
from codejury.providers.mock import MockProvider

from codejury.resources import CAPABILITIES_DIR

_DIFF = """\
+def store_password(pwd: str) -> str:
+    return hashlib.sha256(pwd.encode()).hexdigest()
"""

# What a model would plausibly return for the diff above against authentication.yaml.
_MODEL_REPLY = json.dumps(
    {
        "verdicts": [
            {
                "sub_capability": "password_storage",
                "status": "VULNERABLE",
                "reasoning": "Password hashed with fast unsalted SHA-256",
                "matched_anti": ["PWD-BAD-1"],
                "evidence": [{"file": "auth.py", "line": 2, "code": "hashlib.sha256(pwd.encode())"}],
                "confidence": 0.95,
            },
            {"sub_capability": "jwt_verification", "status": "NOT_PRESENT"},
        ]
    }
)


def test_audit_diff_single_produces_verdicts_from_real_capability():
    cap = load_capability(CAPABILITIES_DIR / "authentication.yaml")
    ctx = AnalysisContext(
        artifact=CodeArtifact(kind="diff", path="auth.py", content=_DIFF),
        capabilities=[cap],
    )
    agent = VerifierAgent(provider=MockProvider(default=_MODEL_REPLY), model="mock")

    result = SingleOrchestrator().run({"verifier": agent}, ctx)

    assert result.error is None
    by_cap = {v.capability: v for v in result.observations}

    # The report covers what was checked: both a VULNERABLE and a NOT_PRESENT verdict.
    assert set(by_cap) == {"authn.password_storage", "authn.jwt_verification"}

    vuln = by_cap["authn.password_storage"]
    assert vuln.status == "VULNERABLE"
    assert vuln.matched_anti == ["PWD-BAD-1"]
    assert vuln.evidence[0].line == 2
    assert by_cap["authn.jwt_verification"].status == "NOT_PRESENT"
