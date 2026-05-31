"""Capability model -- domain knowledge loaded from YAML into typed dataclasses.

A capability is the first-class unit of Application Security knowledge, one per
OWASP ASVS area. Its YAML is readable by the model as a checklist, by a rule
engine because ``signals`` can be grepped, and by a human because the ``why_*``
fields are teaching material.

This module only deserializes YAML into dataclasses; it holds no audit logic.
Unknown keys in the YAML are ignored so the schema can grow without breaking
older loaders.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from codejury.domain.observation import Severity


@dataclass(frozen=True, kw_only=True)
class CorrectPattern:
    """A safe pattern. Matching it supports a SECURE verdict."""

    id: str
    description: str = ""
    signals: list[str] = field(default_factory=list)  # code markers a rule engine can grep
    why_ok: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CorrectPattern:
        return cls(
            id=data["id"],
            description=data.get("description", ""),
            signals=list(data.get("signals", [])),
            why_ok=data.get("why_ok", ""),
        )


@dataclass(frozen=True, kw_only=True)
class AntiPattern:
    """An unsafe pattern. Matching it supports a VULNERABLE verdict."""

    id: str
    description: str = ""
    signals: list[str] = field(default_factory=list)
    cwe: str = ""
    severity: Severity = "MEDIUM"
    why_bad: str = ""
    example_bad: str = ""
    example_good: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AntiPattern:
        return cls(
            id=data["id"],
            description=data.get("description", ""),
            signals=list(data.get("signals", [])),
            cwe=data.get("cwe", ""),
            severity=data.get("severity", "MEDIUM"),
            why_bad=data.get("why_bad", ""),
            example_bad=data.get("example_bad", ""),
            example_good=data.get("example_good", ""),
        )


@dataclass(frozen=True, kw_only=True)
class SubCapability:
    """One checkable dimension within a capability, such as password_storage."""

    name: str
    correct_patterns: list[CorrectPattern] = field(default_factory=list)
    anti_patterns: list[AntiPattern] = field(default_factory=list)

    @classmethod
    def from_dict(cls, name: str, data: dict[str, Any]) -> SubCapability:
        return cls(
            name=name,
            correct_patterns=[CorrectPattern.from_dict(p) for p in data.get("correct_patterns", [])],
            anti_patterns=[AntiPattern.from_dict(p) for p in data.get("anti_patterns", [])],
        )


@dataclass(frozen=True, kw_only=True)
class Capability:
    """A first-class Application Security knowledge unit, one per OWASP ASVS area."""

    id: str
    name: str
    asvs_chapter: str = ""
    description: str = ""
    sub_capabilities: dict[str, SubCapability] = field(default_factory=dict)
    # code patterns that bring this capability into scope for a given artifact
    trigger_signals: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Capability:
        subs = data.get("sub_capabilities") or {}
        return cls(
            id=data["id"],
            name=data["name"],
            asvs_chapter=data.get("asvs_chapter", ""),
            description=data.get("description", ""),
            sub_capabilities={name: SubCapability.from_dict(name, body) for name, body in subs.items()},
            trigger_signals=list(data.get("trigger_signals", [])),
        )


def load_capability(path: str | Path) -> Capability:
    """Load a single capability YAML file into a Capability."""
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a YAML mapping at the top level, got {type(data).__name__}")
    return Capability.from_dict(data)


def load_capabilities(directory: str | Path) -> list[Capability]:
    """Load every ``*.yaml`` capability file in a directory, sorted by name."""
    return [load_capability(p) for p in sorted(Path(directory).glob("*.yaml"))]
