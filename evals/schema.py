"""The shared eval schema: a normalized report from any path, an answer key entry, and the
answer key itself.

These shapes are the public internal API every runner and scorer agrees on. The diff path
and the repo path differ only in how they produce reports, see runners/, then everything
downstream speaks Report and AnswerKey. The answer key never reaches the review under test,
so a high score cannot come from the review reading the key.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from evals.scorers.match import category_of, normalize_endpoint


@dataclass(frozen=True, kw_only=True)
class Report:
    """One reported issue, however a path produced it. Endpoint is stored normalized."""
    name: str
    endpoint: str = ""
    category: str = ""
    files: tuple[str, ...] = ()

    @classmethod
    def make(cls, name: str, endpoint: str, category: str, files) -> "Report":
        return cls(name=name, endpoint=normalize_endpoint(endpoint),
                   category=category_of(category), files=tuple(files))


@dataclass(frozen=True, kw_only=True)
class KeyEntry:
    """A planted issue or a safe lookalike from the answer key."""
    id: str
    entry: str = ""
    file: str = ""
    category: str = ""
    severity: str = ""
    note: str = ""


@dataclass(frozen=True, kw_only=True)
class AnswerKey:
    target: str
    planted: tuple[KeyEntry, ...]
    safe: tuple[KeyEntry, ...]


def _key_entries(rows, *, require_category: bool, where: str) -> tuple[KeyEntry, ...]:
    out: list[KeyEntry] = []
    for i, r in enumerate(rows or []):
        if not isinstance(r, dict):
            raise ValueError(f"{where}[{i}] is not a mapping")
        if "entry" not in r and "file" not in r:
            # invariant: no location means a report can never be matched to it, so a key
            # entry with neither an endpoint nor a file is unscoreable and is rejected loud
            raise ValueError(f"{where}[{i}] has neither entry nor file, it cannot be matched")
        if require_category and not r.get("category"):
            raise ValueError(f"{where}[{i}] has no category")
        out.append(KeyEntry(
            id=str(r.get("id") or f"{where}-{i}"),
            entry=str(r.get("entry", "")),
            file=str(r.get("file", "")),
            category=category_of(str(r.get("category", ""))),
            severity=str(r.get("severity", "")),
            note=str(r.get("note", "")),
        ))
    return tuple(out)


def load_answer_key(path: str | Path) -> AnswerKey:
    """Load and validate an answer key, failing loud on a malformed one rather than
    scoring against a silently empty key. Accepts `planted:` and the legacy `issues:` as
    aliases, so a key authored before the rename loads unchanged."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"answer key {path} is not a mapping")
    planted_rows = data.get("planted", data.get("issues"))
    if planted_rows is None:
        raise ValueError(f"answer key {path} has no planted (or legacy issues) list")
    return AnswerKey(
        target=str(data.get("target", Path(path).stem)),
        planted=_key_entries(planted_rows, require_category=True, where="planted"),
        safe=_key_entries(data.get("safe"), require_category=False, where="safe"),
    )
