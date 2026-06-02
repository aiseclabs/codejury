"""FindingsFilter: hard-rule false-positive suppression after the model returns.

The model is told what not to report, but a second deterministic pass catches the
common noise it still emits: findings in test or mock or fixture code, and
findings below a confidence floor. Returns (kept, dropped) so the dropped set
stays auditable rather than vanishing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from codejury.domain.finding import Finding

# path segments that mark non-production code where a "vulnerability" is usually
# intentional test scaffolding, not a real risk
_NONPROD_PATH = re.compile(r"(^|/)(tests?|test|mocks?|fixtures?|examples?|samples?|conftest)(/|\.|_|$)", re.I)


@dataclass(frozen=True, kw_only=True)
class FindingsFilter:
    min_confidence: float = 0.5
    drop_nonprod_paths: bool = True

    def filter(self, findings: list[Finding]) -> tuple[list[Finding], list[tuple[Finding, str]]]:
        kept: list[Finding] = []
        dropped: list[tuple[Finding, str]] = []
        for f in findings:
            reason = self._drop_reason(f)
            (dropped.append((f, reason)) if reason else kept.append(f))
        return kept, dropped

    def _drop_reason(self, f: Finding) -> str:
        if f.confidence < self.min_confidence:
            return f"confidence {f.confidence:.2f} below floor {self.min_confidence:.2f}"
        if self.drop_nonprod_paths and _NONPROD_PATH.search(f.file or ""):
            return "non-production path (test/mock/fixture/example)"
        return ""
