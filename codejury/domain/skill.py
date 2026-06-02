"""Skill: the first-class unit of Application Security knowledge and check.

A skill is a reviewable data directory, not code:

    data/skills/<id>/
      skill.yaml   manifest: id, name, version, applies_to, standard, cwe,
                   severity, tags
      SKILL.md     the check playbook in prose: what to look for, how to reason,
                   what evidence to collect, how to decide the verdict
      checks/      optional deterministic scripts (call the generic analysis
                   engine); not loaded here

It replaces the old Capability layer: the security knowledge that lived in
structured ``correct_patterns`` / ``anti_patterns`` now lives in the SKILL.md
prose, so a skill carries both the knowledge and the procedure. The manifest
keeps only routing and reporting metadata (``applies_to`` / ``tags`` for the
selector, ``cwe`` / ``severity`` as reporting fallbacks).

This module only deserializes the directory into a typed dataclass; it holds no
audit logic. Unknown manifest keys are ignored so the schema can grow without
breaking older loaders.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, get_args

import yaml

from codejury.domain.observation import Severity

_SEVERITIES = frozenset(get_args(Severity))
_MANIFEST = "skill.yaml"
_PLAYBOOK = "SKILL.md"


@dataclass(frozen=True, kw_only=True)
class Skill:
    """One Application Security check: manifest metadata plus a prose playbook."""

    id: str
    name: str
    version: str = "0"  # declared version; the fingerprint also covers content
    # artifact kinds this skill applies to (api_endpoint, diff, file, function,
    # repo); empty means any. The selector's deterministic pre-filter.
    applies_to: tuple[str, ...] = ()
    standard: str = ""  # e.g. "OWASP ASVS V4" or "OWASP LLM01", for grouping
    cwe: str = ""  # primary CWE, a reporting fallback when the model omits one
    severity: Severity = "MEDIUM"  # default severity, a reporting fallback
    tags: tuple[str, ...] = ()  # coarse routing hints for the selector
    instructions: str = ""  # the SKILL.md playbook, the knowledge and procedure

    @classmethod
    def from_manifest(cls, data: dict[str, Any], *, instructions: str) -> Skill:
        severity = data.get("severity", "MEDIUM")
        if severity not in _SEVERITIES:
            raise ValueError(
                f"skill {data.get('id')!r}: invalid severity {severity!r}; "
                f"expected one of {', '.join(sorted(_SEVERITIES))}"
            )
        return cls(
            id=data["id"],
            name=data["name"],
            version=str(data.get("version", "0")),
            applies_to=tuple(data.get("applies_to", [])),
            standard=data.get("standard", ""),
            cwe=data.get("cwe", ""),
            severity=severity,
            tags=tuple(data.get("tags", [])),
            instructions=instructions,
        )

    def fingerprint(self) -> str:
        """A content hash identifying this skill for cache keys.

        It covers the declared ``version`` and the full manifest and playbook, so
        any edit to skill.yaml or SKILL.md changes it and stale verdicts are never
        served, with no manual bump to forget. Mirrors Capability.fingerprint.
        """
        blob = json.dumps(asdict(self), sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def load_skill(directory: str | Path) -> Skill:
    """Load one skill directory (its skill.yaml manifest plus SKILL.md) into a Skill."""
    path = Path(directory)
    manifest_path = path / _MANIFEST
    playbook_path = path / _PLAYBOOK
    if not manifest_path.is_file():
        raise ValueError(f"{path}: missing {_MANIFEST}")
    if not playbook_path.is_file():
        raise ValueError(f"{path}: missing {_PLAYBOOK}; a skill needs a playbook")
    with open(manifest_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{manifest_path}: expected a YAML mapping, got {type(data).__name__}")
    instructions = playbook_path.read_text(encoding="utf-8")
    try:
        return Skill.from_manifest(data, instructions=instructions)
    except KeyError as exc:
        raise ValueError(f"{manifest_path}: skill manifest missing required key {exc}") from exc
    except ValueError as exc:
        raise ValueError(f"{manifest_path}: {exc}") from exc


def load_skills(directory: str | Path) -> list[Skill]:
    """Load every skill subdirectory (one holding a skill.yaml) under ``directory``,
    sorted by id. A missing or empty directory yields no skills."""
    root = Path(directory)
    if not root.is_dir():
        return []
    skills = [load_skill(child) for child in sorted(root.iterdir()) if (child / _MANIFEST).is_file()]
    return sorted(skills, key=lambda s: s.id)
