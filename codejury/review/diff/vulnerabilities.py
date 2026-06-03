"""Vulnerability classes as data: load the rich markdown definitions and pick the
ones relevant to a diff, to inject into the audit prompt.

Each ``data/vulnerabilities/<class>.md`` has a YAML frontmatter (title, impact,
tags, triggers) and a body with vulnerable/secure examples.
``select_vulnerabilities`` matches a class's triggers against the diff text
(case-insensitive substring), so only the relevant ones are fed to the model
rather than the whole library.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from codejury.mddoc import iter_md_docs
from codejury.resources import VULNERABILITIES_DIR

_IMPACT_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}


@dataclass(frozen=True, kw_only=True)
class Vulnerability:
    id: str
    title: str
    impact: str
    tags: tuple[str, ...]
    triggers: tuple[str, ...]
    body: str


def load_vulnerabilities(directory: str | Path = VULNERABILITIES_DIR) -> list[Vulnerability]:
    items = [
        Vulnerability(
            id=path.stem,
            title=str(meta.get("title", path.stem)),
            impact=str(meta.get("impact", "MEDIUM")).upper(),
            tags=tuple(meta.get("tags", [])),
            triggers=tuple(str(t) for t in meta.get("triggers", [])),
            body=body,
        )
        for path, meta, body in iter_md_docs(directory)
    ]
    return sorted(items, key=lambda v: v.id)


def select_vulnerabilities(diff: str, items: list[Vulnerability], *, limit: int = 6) -> list[Vulnerability]:
    """The classes whose triggers appear in the diff, most-severe first, capped."""
    low = diff.lower()
    matched = [v for v in items if any(t.lower() in low for t in v.triggers)]
    matched.sort(key=lambda v: (_IMPACT_RANK.get(v.impact, 1), v.id), reverse=True)
    return matched[:limit]


def allowed_categories(directory: str | Path = VULNERABILITIES_DIR) -> list[str]:
    """The closed set of finding categories: every vulnerability id. A finding's
    category must be one of these (or 'other'), so findings tie back to a class."""
    return [v.id for v in load_vulnerabilities(directory)]


def normalize_category(category: str, allowed: set[str]) -> str:
    """Map a model-emitted category onto the closed vulnerability-id set: lowercase
    and hyphenate (so `sql_injection` -> `sql-injection`), keep it if it is a known
    id, else `other`. Empty stays empty."""
    if not category:
        return ""
    slug = category.strip().lower().replace("_", "-").replace(" ", "-")
    return slug if slug in allowed else "other"


def vulnerabilities_for_diff(diff: str, *, directory: str | Path = VULNERABILITIES_DIR, limit: int = 6) -> str:
    """The concatenated bodies of the vulnerability classes relevant to the diff,
    for the prompt. Empty when nothing matches, so the prompt omits the block."""
    selected = select_vulnerabilities(diff, load_vulnerabilities(directory), limit=limit)
    return "\n\n---\n\n".join(v.body for v in selected)
