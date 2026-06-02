"""Skill selection: which skills to run on a given target.

Two stages, deterministic first (R4 of the skill refactor):

1. ``applies_to`` filter (pure, no model): a skill that declares ``applies_to``
   runs only on matching artifact kinds; an empty ``applies_to`` means any kind.
   This is the deterministic pre-filter.
2. an optional model router (temperature 0): among the candidates, the model
   picks the relevant skills given each skill's id, name, tags, and standard.
   Reproducible, and cacheable via ``selection_key``.

Without a router, ``select`` returns all candidates, the recall-safe default.
The router only ever narrows the candidate set, and a router that cannot decide
(unparseable reply) falls back to all candidates, so a routing failure never
silently drops a skill.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from codejury.domain.artifact import CodeArtifact
from codejury.domain.skill import Skill
from codejury.infrastructure.cache import normalize_code
from codejury.infrastructure.json_parse import extract_json_object
from codejury.providers.base import Message, Provider

DEFAULT_SELECTION_DIR = Path.home() / ".cache" / "codejury" / "selections"
_SCHEMA = "1"


@dataclass(frozen=True)
class Selector:
    skills: tuple[Skill, ...]

    def candidates(self, artifact: CodeArtifact) -> list[Skill]:
        """Deterministic pre-filter: skills whose applies_to admits this artifact
        kind (an empty applies_to admits any kind), in skill-id order."""
        cands = [s for s in self.skills if not s.applies_to or artifact.kind in s.applies_to]
        return sorted(cands, key=lambda s: s.id)

    def select(self, artifact: CodeArtifact, *, router: SkillRouter | None = None) -> list[Skill]:
        cands = self.candidates(artifact)
        if router is None or not cands:
            return cands
        chosen = router.route(artifact, cands)
        if chosen is None:  # router could not decide: keep every candidate
            return cands
        by_id = {s.id: s for s in cands}
        return [by_id[i] for i in chosen if i in by_id]


_ROUTER_SYSTEM = (
    "You route code to the security review skills worth running on it. You only "
    "narrow a given candidate list; you never invent skills. Respond with a single "
    "JSON object and nothing else."
)


class SkillRouter:
    """Model-backed router: among candidate skills, pick the ones relevant to a
    piece of code. Runs at temperature 0 (set by the provider), so the decision is
    reproducible for the same input."""

    def __init__(self, *, provider: Provider, model: str, max_tokens: int = 512) -> None:
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens

    def route(self, artifact: CodeArtifact, candidates: list[Skill]) -> list[str] | None:
        result = self._provider.complete(
            system=_ROUTER_SYSTEM,
            messages=[Message(role="user", content=_router_prompt(artifact, candidates))],
            model=self._model,
            max_tokens=self._max_tokens,
        )
        obj = extract_json_object(result.text)
        if not obj or not isinstance(obj.get("skills"), list):
            return None  # undecidable: caller falls back to all candidates
        valid = {s.id for s in candidates}
        return [str(i) for i in obj["skills"] if i in valid]


def _router_prompt(artifact: CodeArtifact, candidates: list[Skill]) -> str:
    lines = ["Candidate skills:"]
    for s in candidates:
        tags = f" tags=[{', '.join(s.tags)}]" if s.tags else ""
        standard = f" ({s.standard})" if s.standard else ""
        lines.append(f"- {s.id}: {s.name}{standard}{tags}")
    listing = "\n".join(lines)
    return (
        "Choose which of the candidate skills are worth running on the code below. "
        "Include a skill when the code plausibly exercises what it checks; leave out "
        "skills with no bearing on this code. When unsure, include it.\n\n"
        f"{listing}\n\n"
        f"Code ({artifact.path}):\n```\n{artifact.content}\n```\n\n"
        'Respond with a single JSON object exactly like: {"skills": ["id1", "id2"]}'
    )


def selection_key(artifact: CodeArtifact, candidates: list[Skill], *, router_model: str) -> str:
    """A content hash identifying a routing decision, so the model router runs
    once per (code, candidate skills, model) and is reused thereafter."""
    payload = {
        "schema": _SCHEMA,
        "kind": artifact.kind,
        "path": artifact.path,
        "code": normalize_code(artifact.content),
        "context": normalize_code(artifact.context),
        "candidates": sorted(f"{s.id}@{s.fingerprint()}" for s in candidates),
        "router_model": router_model,
    }
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class SelectionCache:
    """A content-addressed store of routing decisions (a list of skill ids),
    keyed by ``selection_key``. Disk-backed, one JSON file per key."""

    def __init__(self, directory: str | Path = DEFAULT_SELECTION_DIR) -> None:
        self._dir = Path(directory)

    def get(self, key: str) -> list[str] | None:
        path = self._dir / f"{key}.json"
        if not path.exists():
            return None
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (ValueError, OSError):  # corrupt or half-written entry: treat as a miss
            return None
        return [str(i) for i in data] if isinstance(data, list) else None

    def put(self, key: str, skill_ids: list[str]) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        path = self._dir / f"{key}.json"
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(list(skill_ids), f, ensure_ascii=False)
        os.replace(tmp, path)
