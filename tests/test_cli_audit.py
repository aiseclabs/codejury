import json
from pathlib import Path

from codejury.cli import _render_audit, audit
from codejury.domain.capability import load_capability
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
