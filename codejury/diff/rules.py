"""Security rules as data: load the rich markdown rules and pick the ones
relevant to a diff, to inject into the audit prompt.

Each ``data/rules/<class>.md`` has a YAML frontmatter (title, impact, tags,
triggers) and a body with vulnerable/secure examples. ``select_rules`` matches a
rule's triggers against the diff text (case-insensitive substring), so only the
on-topic rules are fed to the model rather than the whole library.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from codejury.mddoc import iter_md_docs
from codejury.resources import RULES_DIR

_IMPACT_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}


@dataclass(frozen=True, kw_only=True)
class Rule:
    id: str
    title: str
    impact: str
    tags: tuple[str, ...]
    triggers: tuple[str, ...]
    body: str


def load_rules(directory: str | Path = RULES_DIR) -> list[Rule]:
    rules = [
        Rule(
            id=path.stem,
            title=str(meta.get("title", path.stem)),
            impact=str(meta.get("impact", "MEDIUM")).upper(),
            tags=tuple(meta.get("tags", [])),
            triggers=tuple(str(t) for t in meta.get("triggers", [])),
            body=body,
        )
        for path, meta, body in iter_md_docs(directory)
    ]
    return sorted(rules, key=lambda r: r.id)


def select_rules(diff: str, rules: list[Rule], *, limit: int = 6) -> list[Rule]:
    """The rules whose triggers appear in the diff, most-severe first, capped."""
    low = diff.lower()
    matched = [r for r in rules if any(t.lower() in low for t in r.triggers)]
    matched.sort(key=lambda r: (_IMPACT_RANK.get(r.impact, 1), r.id), reverse=True)
    return matched[:limit]


def allowed_categories(directory: str | Path = RULES_DIR) -> list[str]:
    """The closed set of finding categories: every rule id. A finding's category
    must be one of these (or 'other'), so findings tie back to a rule."""
    return [r.id for r in load_rules(directory)]


def normalize_category(category: str, allowed: set[str]) -> str:
    """Map a model-emitted category onto the closed rule-id set: lowercase and
    hyphenate (so `sql_injection` -> `sql-injection`), keep it if it is a rule id,
    else `other`. Empty stays empty."""
    if not category:
        return ""
    slug = category.strip().lower().replace("_", "-").replace(" ", "-")
    return slug if slug in allowed else "other"


def rules_for_diff(diff: str, *, directory: str | Path = RULES_DIR, limit: int = 6) -> str:
    """The concatenated bodies of the rules relevant to the diff, for the prompt.
    Empty when nothing matches, so the prompt simply omits the rules block."""
    selected = select_rules(diff, load_rules(directory), limit=limit)
    return "\n\n---\n\n".join(r.body for r in selected)
