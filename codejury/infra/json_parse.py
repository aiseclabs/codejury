"""Best-effort extraction of a JSON object from model output.

Models often wrap JSON in prose or code fences despite instructions. This
recovers the object with no third-party dependency: try a direct parse, then a
fenced ```json block, then the first balanced-brace span in the text.
"""

from __future__ import annotations

import json
import re

# Greedy so a fenced block with nested braces is captured whole.
_FENCE = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.DOTALL)


def extract_json_object(text: str) -> dict | None:
    """Return the first JSON object found in `text`, or None if there is none."""
    text = text.strip()

    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        pass

    fenced = _FENCE.search(text)
    if fenced:
        try:
            obj = json.loads(fenced.group(1))
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass

    return _first_balanced_object(text)


def _first_balanced_object(text: str) -> dict | None:
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(text[start : i + 1])
                except json.JSONDecodeError:
                    start = -1
                    continue
                if isinstance(obj, dict):
                    return obj
    return None
