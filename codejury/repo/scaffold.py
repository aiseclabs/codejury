"""Whole-repo review scaffold: set up the agent's workspace, do not run a pipeline.

The `review repo` path. Whole-repo review is too large for a single LLM call, so
codejury does not run it as a pipeline. Instead it scaffolds a workspace for an
interactive agent (Claude Code, Codex) and hands over the methodology: it creates
the api/issues/analysis directories, copies the review-memory template, seeds the
API inventory from a deterministic RepoModel scan, and returns the methodology
text to print.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from codejury.repo.model import build_repo_model_from_dir
from codejury.resources import AGENT_DIR

_METHODOLOGY = AGENT_DIR / "full-review.md"
_MEMORY_TEMPLATE = AGENT_DIR / "security-review-memory.md"


@dataclass(frozen=True, kw_only=True)
class ScaffoldResult:
    project: str
    workspace: Path
    methodology: str
    memory_path: Path
    entrypoints: int
    created: list[str] = field(default_factory=list)


def _entrypoints_md(model) -> str:
    http = [e for e in model.entrypoints if e.kind == "http"]
    cli = [e for e in model.entrypoints if e.kind == "cli"]
    lines = ["# API Entrypoints (seeded from a deterministic scan)", "",
             "Status legend: ❌ not reviewed · ⚠️ to deepen · ✅ reviewed", ""]
    if http:
        lines += ["## HTTP routes", ""]
        lines += [f"- ❌ `{e.method or '-'} {e.route or '-'}`  {e.file}::{e.function}  [{e.framework}]" for e in http]
        lines.append("")
    if cli:
        lines += ["## CLI commands", ""]
        lines += [f"- ❌ {e.file}::{e.function}  [{e.framework}]" for e in cli]
        lines.append("")
    if not model.entrypoints:
        lines.append("(no entrypoints auto-detected; enumerate them manually while reading the code)")
    return "\n".join(lines) + "\n"


def scaffold(target: str | Path, workspace: str | Path) -> ScaffoldResult:
    target = Path(target).resolve()
    project = target.name
    ws = Path(workspace) / project
    created: list[str] = []
    for sub in ("api", "issues", "analysis"):
        d = ws / sub
        if not d.exists():
            d.mkdir(parents=True, exist_ok=True)
            created.append(str(d))

    memory_path = ws / "security-review-memory.md"
    if not memory_path.exists():  # never clobber an edited memory
        template = _MEMORY_TEMPLATE.read_text(encoding="utf-8").replace("<project>", project)
        memory_path.write_text(template, encoding="utf-8")
        created.append(str(memory_path))

    model = build_repo_model_from_dir(target)
    (ws / "api" / "_entrypoints.md").write_text(_entrypoints_md(model), encoding="utf-8")

    return ScaffoldResult(
        project=project,
        workspace=ws,
        methodology=_METHODOLOGY.read_text(encoding="utf-8"),
        memory_path=memory_path,
        entrypoints=len(model.entrypoints),
        created=created,
    )
