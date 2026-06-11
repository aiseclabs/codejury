"""The unit reviewer output contract, shared by both Repo Review backends, the model
reviewer in `reviewer.py` and the claude-cli agent reviewer in `agent.py`. It lives in its
own module so neither backend reaches into the other for it, the shape is one contract both
emit and parse.
"""

from __future__ import annotations

JSON_SHAPE = (
    '{"findings": [{"title": "...", "category": "<class id>", '
    '"endpoint": "METHOD /path or empty", "file": "path", "line": 0, '
    '"severity": "CRITICAL|HIGH|MEDIUM|LOW", "evidence": "controlling fact at file:line", '
    '"status": "confirmed|blocked"}]}'
)


def lens_line(lens: str) -> str:
    if not lens:
        return "Review for every high-impact class.\n\n"
    return (f"This pass LEADS WITH THE {lens.upper()} LENS: prioritize finding {lens} "
            f"issues across this unit, while still reporting any other class you see.\n\n")
