"""Whole-repo review scaffold: set up the agent's workspace, do not run a pipeline.

The `review repo` path. Whole-repo review is too large for a single LLM call, so
it does not run as a pipeline. Instead it scaffolds a workspace for an
interactive agent such as Claude Code or Codex and hands over the methodology: it creates
the entrypoints/issues/analysis directories, copies the review-memory template,
seeds the detected stack guides and the candidate entrypoint files, and returns
the methodology text to print.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

from codejury.detection import load_detection
from codejury.guides import (
    Guide,
    entrypoint_globs,
    entrypoint_markers,
    logic_layer_globs,
    select_guides,
)
from codejury.review.repo.model import build_repo_model_from_dir, candidate_entrypoint_files, logic_layer_files
from codejury.resources import METHODOLOGIES_DIR

_METHODOLOGY = METHODOLOGIES_DIR / "repo-review.md"
_MEMORY_TEMPLATE = METHODOLOGIES_DIR / "memory-template.md"

_DETECT_PER_FILE = 16_000   # bytes read per file
_DETECT_TOTAL = 8_000_000   # bytes of source sampled overall


@dataclass(frozen=True, kw_only=True)
class ScaffoldResult:
    project: str
    workspace: Path
    methodology: str
    memory_path: Path
    candidate_files: tuple[str, ...] = ()   # files a matched guide flags as likely entrypoints
    trace_targets: tuple[str, ...] = ()     # downstream logic-layer files to trace into
    guides: tuple[str, ...] = ()
    created: list[str] = field(default_factory=list)
    had_prior_run: bool = False             # the workspace already held a previous review's output
    cleared: list[str] = field(default_factory=list)  # paths removed by a fresh run, MEMORY.md included


def _read_manifests(target: Path) -> str:
    parts: list[str] = []
    for name in load_detection().manifests:
        p = target / name
        try:
            if p.is_file():
                parts.append(p.read_text(encoding="utf-8"))
        except OSError:
            pass
    return "\n".join(parts)


def _source_sample(target: Path, files: list[str]) -> str:
    """A bounded sample of source and config content, so detection can fire on
    import markers and language-neutral content tokens such as a protocol's wire
    fields. Kept separate from the manifests so a dependency name does not
    false-match a word that happens to appear in source."""
    detection_extensions = load_detection().detection_extensions
    parts: list[str] = []
    total = 0
    for f in files:
        if Path(f).suffix.lower() not in detection_extensions:
            continue
        p = target / f
        try:
            chunk = p.read_text(encoding="utf-8")[:_DETECT_PER_FILE]
        except (OSError, UnicodeDecodeError):
            continue
        parts.append(chunk)
        total += len(chunk)
        if total >= _DETECT_TOTAL:
            break
    return "\n".join(parts)


def _stack_md(guides: list[Guide]) -> str:
    if not guides:
        return ("# Detected stack\n\n"
                "No language or framework guide matched. Rely on the methodology and "
                "your own knowledge of the stack.\n")
    langs = [g.id for g in guides if g.kind == "language"]
    fws = [g for g in guides if g.kind == "framework"]
    protocols = [g.id for g in guides if g.kind == "protocol"]
    # a framework is shown under the language it belongs to
    fw_labels = [f"{g.id} ({g.language})" if g.language else g.id for g in fws]
    lines = ["# Detected stack", "",
             f"Languages: {', '.join(langs) or '-'}",
             f"Frameworks: {', '.join(fw_labels) or '-'}",
             f"Protocols: {', '.join(protocols) or '-'}", ""]
    for g in guides:
        lines += ["---", "", g.body, ""]
    return "\n".join(lines) + "\n"


def _entrypoints_md(candidates: list[str]) -> str:
    lines = ["# Entrypoints", "",
             "Files the detected stack flags as likely to define entrypoints, see "
             "`_stack.md`. Open each, identify the actual entrypoints, and add "
             "non-HTTP sources such as deserialization, queues, and file parsers here too.", "",
             "Status legend: ❌ not reviewed · ⚠️ to deepen · ✅ reviewed", ""]
    if candidates:
        lines += [f"- ❌ {f}" for f in candidates]
    else:
        lines.append("No candidate files flagged. Enumerate entrypoints by reading "
                      "the code, guided by `_stack.md`.")
    return "\n".join(lines) + "\n"


def _trace_targets_md(layers: list[str]) -> str:
    lines = ["# Trace Targets, the Downstream Logic Layers", "",
             "Files below the entrypoints where the business logic, state, and data "
             "access live, flagged by the detected stack's conventions such as "
             "controllers, managers, dao, and services. They are not entrypoints. "
             "When you trace an attack path from a source, follow it into these "
             "files to the real sink, since the flaw is usually here and not in the "
             "view, for example a missing lock in a dao or a skipped check in a "
             "manager. Do not close an entrypoint until its path is traced through "
             "these layers to a sink or cleared.", ""]
    if layers:
        lines += [f"- {f}" for f in layers]
    else:
        lines.append("No logic-layer files flagged. Trace by reading the imports and "
                      "calls out of each entrypoint, guided by `_stack.md`.")
    return "\n".join(lines) + "\n"


_ROUNDS_TEMPLATE = """\
# Review Rounds

Log one entry per round. The review is complete only when the Completeness Gate
in the methodology passes: every entrypoint resolved to ✅, each traced through
the downstream logic layers to a sink or cleared, and two consecutive rounds add
nothing new. A short run with an empty ledger is an incomplete review, not a
clean one.

## Round 1
- Sources reviewed:
- Traced to a sink, see `analysis/`:
- New issues, see `issues/`:
- Still open, ❌ or ⚠️ in `entrypoints/_entrypoints.md`:
"""


def _has_prior_run(ws: Path) -> bool:
    """True when the workspace already holds a previous review's output, not just
    a bare scaffold. Findings, PoCs, a logged round ledger, or a hand-built
    entrypoint inventory all count. The regenerated seeds alone do not."""
    if not ws.exists():
        return False
    for sub in ("issues", "pocs"):
        d = ws / sub
        if d.is_dir() and any(d.iterdir()):
            return True
    rounds = ws / "analysis" / "_rounds.md"
    if rounds.exists() and rounds.read_text(encoding="utf-8") != _ROUNDS_TEMPLATE:
        return True
    inv = ws / "entrypoints"
    if inv.is_dir() and any(p.name != "_entrypoints.md" for p in inv.iterdir()):
        return True
    return False


def _clear_prior_run(ws: Path) -> list[str]:
    """Remove a previous review's output so a fresh run starts clean. This wipes
    MEMORY.md too, so the cross-run memory of confirmed false positives and fixed
    issues is reset, the run starts from a blank slate with no stale judgments
    suppressing a finding."""
    removed: list[str] = []
    for child in ws.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
        removed.append(str(child))
    return removed


def scaffold(target: str | Path, workspace: str | Path, *, fresh: bool = False) -> ScaffoldResult:
    target = Path(target).resolve()
    project = target.name
    ws = Path(workspace) / project
    had_prior_run = _has_prior_run(ws)
    cleared: list[str] = []
    if fresh and ws.exists():
        cleared = _clear_prior_run(ws)
    created: list[str] = []
    for sub in ("entrypoints", "issues", "pocs", "analysis"):
        d = ws / sub
        if not d.exists():
            d.mkdir(parents=True, exist_ok=True)
            created.append(str(d))

    memory_path = ws / "MEMORY.md"
    if not memory_path.exists():  # never clobber an edited memory
        template = _MEMORY_TEMPLATE.read_text(encoding="utf-8").replace("<project>", project)
        memory_path.write_text(template, encoding="utf-8")
        created.append(str(memory_path))

    model = build_repo_model_from_dir(target)

    # detect the stack and seed its review guides
    guides = select_guides(
        model.files,
        manifest_text=_read_manifests(target),
        source_text=_source_sample(target, model.files),
    )
    (ws / "_stack.md").write_text(_stack_md(guides), encoding="utf-8")

    # flag candidate entrypoint files via the matched guides' globs and by
    # scanning content for the entrypoint markers a guide declares
    candidates = candidate_entrypoint_files(
        model.files, root=target,
        globs=entrypoint_globs(guides), markers=entrypoint_markers(guides),
    )
    (ws / "entrypoints" / "_entrypoints.md").write_text(_entrypoints_md(candidates), encoding="utf-8")

    # surface the downstream logic layers to trace into, so a path is followed
    # past the view into the manager or dao where the flaw usually lives
    layers = logic_layer_files(model.files, globs=logic_layer_globs(guides))
    (ws / "analysis" / "_trace_targets.md").write_text(_trace_targets_md(layers), encoding="utf-8")

    # seed a round ledger so depth is a visible obligation, never clobber an edited one
    rounds_path = ws / "analysis" / "_rounds.md"
    if not rounds_path.exists():
        rounds_path.write_text(_ROUNDS_TEMPLATE, encoding="utf-8")
        created.append(str(rounds_path))

    return ScaffoldResult(
        project=project,
        workspace=ws,
        methodology=_METHODOLOGY.read_text(encoding="utf-8"),
        memory_path=memory_path,
        candidate_files=tuple(candidates),
        trace_targets=tuple(layers),
        guides=tuple(g.id for g in guides),
        created=created,
        had_prior_run=had_prior_run,
        cleared=cleared,
    )
