import json

import pytest

from codejury.cli import _render_audit, _render_observation, audit, make_provider
from codejury.domain.observation import Concession, Finding, Verdict
from codejury.domain.skill import Skill
from codejury.providers.anthropic import AnthropicProvider
from codejury.providers.litellm import LiteLLMProvider
from codejury.providers.mock import MockProvider
from codejury.providers.openai import OpenAIProvider

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

_AUTHN = Skill(id="authn", name="Authentication", cwe="CWE-916", instructions="check password hashing")

# SkillRunner drops a VULNERABLE verdict with no location, so the mock carries one.
_REPLY = json.dumps(
    {"verdicts": [{"dimension": "password_storage", "status": "VULNERABLE",
                   "evidence": [{"file": "auth.py", "line": 1, "code": "sha256"}]}]}
)


def test_audit_runs_per_changed_file():
    results = audit(_TWO_FILE_DIFF, [_AUTHN], provider=MockProvider(default=_REPLY), model="mock")

    assert [path for path, _ in results] == ["auth.py", "safe.py"]
    _, first_result = results[0]
    assert first_result.observations[0].capability == "authn.password_storage"
    assert first_result.observations[0].status == "VULNERABLE"


def test_render_groups_by_file_and_shows_the_verdict():
    results = audit(_TWO_FILE_DIFF, [_AUTHN], provider=MockProvider(default=_REPLY), model="mock")
    rendered = _render_audit(results)
    assert "== auth.py ==" in rendered
    assert "VULNERABLE" in rendered


def test_render_handles_empty_diff():
    assert _render_audit([]) == "no changed files in diff"


_ONE_FILE_DIFF = """\
diff --git a/auth.py b/auth.py
--- a/auth.py
+++ b/auth.py
@@ -1,1 +1,1 @@
+    return hashlib.sha256(pwd.encode()).hexdigest()
"""


def test_multi_agent_strategy_not_yet_wired_for_skills():
    # debate/reflexion/challenge/adaptive on skills arrive with R5b; until then a
    # skill audit with such a strategy fails loudly rather than silently.
    with pytest.raises(NotImplementedError):
        audit(_ONE_FILE_DIFF, [_AUTHN], provider=MockProvider(default="{}"), model="m", strategy="debate")


@pytest.mark.parametrize(
    "name,cls",
    [("anthropic", AnthropicProvider), ("openai", OpenAIProvider), ("litellm", LiteLLMProvider)],
)
def test_make_provider_selects_backend(name, cls):
    assert isinstance(make_provider(name), cls)


def test_render_observation_covers_each_kind():
    verdict = _render_observation(Verdict(capability="authn.x", status="VULNERABLE", matched_anti=["PWD-BAD-1"]))
    finding = _render_observation(Finding(title="weak hash", severity="HIGH", cwe="CWE-916"))
    concession = _render_observation(Concession(target="weak hash", reason="just a checksum"))
    assert "VULNERABLE" in verdict and "PWD-BAD-1" in verdict
    assert "FINDING" in finding and "weak hash" in finding and "CWE-916" in finding
    assert "DISMISSED" in concession and "just a checksum" in concession


def test_scan_audits_each_file_in_a_tree(tmp_path):
    from codejury.cli import scan

    (tmp_path / "pkg").mkdir()
    (tmp_path / "a.py").write_text("x = hashlib.sha256(pwd)\n", encoding="utf-8")
    (tmp_path / "pkg" / "b.py").write_text("y = bcrypt.hashpw(pwd, salt)\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("ignored\n", encoding="utf-8")  # wrong extension

    reply = json.dumps(
        {"verdicts": [{"dimension": "password_storage", "status": "VULNERABLE",
                       "evidence": [{"file": "a.py", "line": 1, "code": "sha256"}]}]}
    )
    results = scan(str(tmp_path), [_AUTHN], provider=MockProvider(default=reply), model="m", strategy="pipeline")

    assert [path for path, _ in results] == ["a.py", "pkg/b.py"]  # only .py, sorted, relative
    assert results[0][1].observations[0].capability == "authn.password_storage"
