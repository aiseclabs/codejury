"""FindingsFilter: hard-rule false-positive suppression after the model returns.

The model is told what not to report, but a second deterministic pass drops the
common noise it still emits: findings below a confidence floor, and findings in
test code. Test detection is conservative, a real test directory segment or a
test-file naming convention, not a bare ``sample_``/``mock_`` prefix, so a
production file like ``sample_rate.py`` is not silently suppressed. Operators can
add their own excluded path segments. Returns (kept, dropped) so the dropped set
stays auditable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# directory segments that mark test code
_TEST_DIRS = frozenset({
    "test", "tests", "__tests__", "__mocks__", "mocks", "fixtures", "testdata", "e2e", "spec", "specs",
})


def _is_test_path(path: str) -> bool:
    parts = path.replace("\\", "/").split("/")
    if any(p in _TEST_DIRS for p in parts[:-1]):  # a directory segment, not the filename
        return True
    name = parts[-1].lower()
    if name == "conftest.py":
        return True
    stem = name.rsplit(".", 1)[0]
    return (
        stem.startswith("test_")
        or stem.endswith("_test")
        or stem.endswith(".test")
        or stem.endswith(".spec")
    )


@dataclass(frozen=True, kw_only=True)
class FindingsFilter:
    min_confidence: float = 0.5
    drop_test_paths: bool = True
    exclude_paths: tuple[str, ...] = field(default_factory=tuple)  # operator-configured path substrings

    def filter(self, findings: list) -> tuple[list, list[tuple[object, str]]]:
        kept: list = []
        dropped: list[tuple[object, str]] = []
        for f in findings:
            reason = self._drop_reason(f)
            (dropped.append((f, reason)) if reason else kept.append(f))
        return kept, dropped

    def _drop_reason(self, f) -> str:
        if f.confidence < self.min_confidence:
            return f"confidence {f.confidence:.2f} below floor {self.min_confidence:.2f}"
        path = f.file or ""
        if self.drop_test_paths and _is_test_path(path):
            return "test path (test/mock/fixture directory or test-file naming)"
        match = next((e for e in self.exclude_paths if e and e in path), None)
        if match:
            return f"excluded path ({match})"
        return ""
