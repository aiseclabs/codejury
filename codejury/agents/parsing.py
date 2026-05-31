"""Shared coercion from loosely-typed model JSON into domain values.

Agents parse model output that may omit, mistype, or invent fields. These
helpers coerce defensively -- they never raise on bad input, they fall back.
"""

from __future__ import annotations

from codejury.domain.observation import Evidence


def str_list(value: object) -> list[str]:
    return [str(x) for x in value] if isinstance(value, list) else []


def to_float(value: object, default: float) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def one_of(value: object, allowed: set[str], default: str) -> str:
    return value if value in allowed else default


def to_evidence(items: object) -> list[Evidence]:
    if not isinstance(items, list):
        return []
    out: list[Evidence] = []
    for e in items:
        if not isinstance(e, dict):
            continue
        line = e.get("line")
        out.append(
            Evidence(
                file=str(e.get("file", "")),
                line=line if isinstance(line, int) else None,
                code=str(e.get("code", "")),
                note=str(e.get("note", "")),
            )
        )
    return out
