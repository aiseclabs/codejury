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

import yaml

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


def _parse(path: Path) -> Rule | None:
    text = path.read_text(encoding="utf-8")
    meta: dict = {}
    body = text
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) == 3:
            meta = yaml.safe_load(parts[1]) or {}
            body = parts[2].strip()
    return Rule(
        id=path.stem,
        title=str(meta.get("title", path.stem)),
        impact=str(meta.get("impact", "MEDIUM")).upper(),
        tags=tuple(meta.get("tags", [])),
        triggers=tuple(str(t) for t in meta.get("triggers", [])),
        body=body,
    )


def load_rules(directory: str | Path = RULES_DIR) -> list[Rule]:
    root = Path(directory)
    if not root.is_dir():
        return []
    rules = [_parse(p) for p in root.glob("*.md") if p.name != "SKILL.md"]
    return sorted([r for r in rules if r], key=lambda r: r.id)


def select_rules(diff: str, rules: list[Rule], *, limit: int = 6) -> list[Rule]:
    """The rules whose triggers appear in the diff, most-severe first, capped."""
    low = diff.lower()
    matched = [r for r in rules if any(t.lower() in low for t in r.triggers)]
    matched.sort(key=lambda r: (_IMPACT_RANK.get(r.impact, 1), r.id), reverse=True)
    return matched[:limit]


def rules_for_diff(diff: str, *, directory: str | Path = RULES_DIR, limit: int = 6) -> str:
    """The concatenated bodies of the rules relevant to the diff, for the prompt.
    Empty when nothing matches, so the prompt simply omits the rules block."""
    selected = select_rules(diff, load_rules(directory), limit=limit)
    return "\n\n---\n\n".join(r.body for r in selected)
