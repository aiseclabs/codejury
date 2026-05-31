import json
from pathlib import Path

from codejury.cli import _render_audit, _render_observation, audit
from codejury.domain.capability import Capability, load_capability
from codejury.domain.observation import Concession, Finding, Verdict
from codejury.providers.mock import MockProvider

CAPABILITIES_DIR = Path(__file__).resolve().parent.parent / "capabilities"

_TWO_FILE_DIFF = """\
diff --git a/auth.py b/auth.py
--- a/auth.py
+++ b/auth.py
@@ -1,1 +1,1 @@
+    return hashlib.sha256(pwd.encode()).hexdigest()
diff --git a/safe.py b/safe.py
--- a/safe.py
+++ b/safe.py
@@ -1,1 +1,1 @@
+    return bcrypt.hashpw(pwd, bcrypt.gensalt())
"""

_REPLY = json.dumps(
    {"verdicts": [{"sub_capability": "password_storage", "status": "VULNERABLE", "matched_anti": ["PWD-BAD-1"]}]}
)


def test_audit_runs_per_changed_file():
    cap = load_capability(CAPABILITIES_DIR / "authentication.yaml")
    results = audit(_TWO_FILE_DIFF, [cap], provider=MockProvider(default=_REPLY), model="mock")

    assert [path for path, _ in results] == ["auth.py", "safe.py"]
    first_path, first_result = results[0]
    assert first_result.observations[0].capability == "authn.password_storage"
    assert first_result.observations[0].status == "VULNERABLE"


def test_render_groups_by_file_and_shows_matched_patterns():
    cap = load_capability(CAPABILITIES_DIR / "authentication.yaml")
    results = audit(_TWO_FILE_DIFF, [cap], provider=MockProvider(default=_REPLY), model="mock")
    rendered = _render_audit(results)
    assert "== auth.py ==" in rendered
    assert "VULNERABLE" in rendered
    assert "PWD-BAD-1" in rendered


def test_render_handles_empty_diff():
    assert _render_audit([]) == "no changed files in diff"


_ONE_FILE_DIFF = """\
diff --git a/auth.py b/auth.py
--- a/auth.py
+++ b/auth.py
@@ -1,1 +1,1 @@
+    return hashlib.sha256(pwd.encode()).hexdigest()
"""


def test_debate_strategy_wires_finder_challenger_judge():
    # Two identical rounds -> debate converges; each round is finder, challenger, judge.
    rounds = []
    for _ in range(2):
        rounds += [
            json.dumps({"findings": [{"title": "weak hash", "severity": "HIGH"}]}),
            json.dumps({"rebuttals": [], "new_findings": []}),
            json.dumps({"surviving": [{"title": "weak hash", "severity": "HIGH"}], "dismissed": []}),
        ]
    provider = MockProvider(responses=rounds, default="{}")
    cap = Capability(id="authn", name="Authentication")

    results = audit(_ONE_FILE_DIFF, [cap], provider=provider, model="m", strategy="debate")

    _, result = results[0]
    findings = [o for o in result.observations if isinstance(o, Finding)]
    assert [f.title for f in findings] == ["weak hash"]
    assert len(provider.calls) == 6  # 2 rounds * 3 roles


def test_render_observation_covers_each_kind():
    verdict = _render_observation(Verdict(capability="authn.x", status="VULNERABLE", matched_anti=["PWD-BAD-1"]))
    finding = _render_observation(Finding(title="weak hash", severity="HIGH", cwe="CWE-916"))
    concession = _render_observation(Concession(target="weak hash", reason="just a checksum"))
    assert "VULNERABLE" in verdict and "PWD-BAD-1" in verdict
    assert "FINDING" in finding and "weak hash" in finding and "CWE-916" in finding
    assert "DISMISSED" in concession and "just a checksum" in concession
