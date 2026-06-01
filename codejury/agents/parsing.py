"""Shared coercion from loosely-typed model JSON into domain values.

Agents parse model output that may omit, mistype, or invent fields. These
helpers coerce defensively: they never raise on bad input, they fall back.
"""

import math

from codejury.domain.observation import Evidence


def str_list(value: object) -> list[str]:
    return [str(x) for x in value] if isinstance(value, list) else []


def to_float(value: object, default: float) -> float:
    # reject bool (it is an int subclass) and non-finite values (json.loads accepts
    # NaN/Infinity); a NaN confidence would silently corrupt every downstream sort.
    if isinstance(value, bool):
        return default
    try:
        result = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return result if math.isfinite(result) else default


def one_of(value: object, allowed: set[str], default: str) -> str:
    # `value in allowed` would raise TypeError on an unhashable model value
    # (e.g. status -> [] or {}); guard so bad input falls back, never raises.
    return value if isinstance(value, str) and value in allowed else default


def to_evidence(items: object) -> list[Evidence]:
    if not isinstance(items, list):
        return []
    out: list[Evidence] = []
    for e in items:
        if not isinstance(e, dict):
            continue
        line = e.get("line")
        # a location needs a real 1-based line; reject 0, negatives, and bool (an int subclass)
        valid_line = line if isinstance(line, int) and not isinstance(line, bool) and line >= 1 else None
        out.append(Evidence(file=str(e.get("file", "")), line=valid_line, code=str(e.get("code", ""))))
    return out
