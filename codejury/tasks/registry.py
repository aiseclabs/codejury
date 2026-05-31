"""Load Task presets from YAML files."""

from __future__ import annotations

from pathlib import Path

import yaml

from codejury.tasks.base import Task


def load_task(path: str | Path) -> Task:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a YAML mapping at the top level, got {type(data).__name__}")
    return Task.from_dict(data)


def load_tasks(directory: str | Path) -> dict[str, Task]:
    """Load every ``*.yaml`` task in a directory, keyed by task name."""
    return {task.name: task for task in (load_task(p) for p in sorted(Path(directory).glob("*.yaml")))}
