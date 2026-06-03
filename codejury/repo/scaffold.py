"""Whole-repo review scaffold: set up the agent's workspace, do not run a pipeline.

The `review repo` path. Whole-repo review is too large for a single LLM call, so
it does not run as a pipeline. Instead it scaffolds a workspace for an
interactive agent (Claude Code, Codex) and hands over the methodology: it creates
the entrypoints/issues/analysis directories, copies the review-memory template,
seeds the detected stack guides and the candidate entrypoint files, and returns
the methodology text to print.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from codejury.guides import Guide, entrypoint_globs, entrypoint_markers, select_guides
from codejury.repo.model import build_repo_model_from_dir, candidate_entrypoint_files
from codejury.resources import METHODOLOGY_DIR

_METHODOLOGY = METHODOLOGY_DIR / "repo-review.md"
_MEMORY_TEMPLATE = METHODOLOGY_DIR / "security-review-memory.md"

# top-level dependency manifests scanned to detect the stack (content, not names)
_MANIFESTS = (
    "requirements.txt", "requirements-dev.txt", "pyproject.toml", "setup.py", "Pipfile",
    "package.json", "go.mod", "Gemfile", "pom.xml", "build.gradle", "Cargo.toml", "composer.json",
)

# source and config extensions sampled so language-neutral content tokens, such
# as a protocol's wire fields, can be detected regardless of the stack
_DETECT_EXT = frozenset({
    ".py", ".js", ".mjs", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java", ".kt",
    ".php", ".cs", ".rs", ".scala", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env",
})
_DETECT_PER_FILE = 16_000   # bytes read per file
_DETECT_TOTAL = 8_000_000   # bytes of source sampled overall


@dataclass(frozen=True, kw_only=True)
class ScaffoldResult:
    project: str
    workspace: Path
    methodology: str
    memory_path: Path
    candidate_files: tuple[str, ...] = ()   # files a matched guide flags as likely entrypoints
    guides: tuple[str, ...] = ()
    created: list[str] = field(default_factory=list)


def _read_manifests(target: Path) -> str:
    parts: list[str] = []
    for name in _MANIFESTS:
        p = target / name
        try:
            if p.is_file():
                parts.append(p.read_text(encoding="utf-8"))
        except OSError:
            pass
    return "\n".join(parts)


def _detection_text(target: Path, files: list[str]) -> str:
    """The dependency manifests plus a bounded sample of source and config
    content, so detection can fire on language-neutral content tokens, not only
    on per-ecosystem dependency names."""
    parts = [_read_manifests(target)]
    total = 0
    for f in files:
        if Path(f).suffix.lower() not in _DETECT_EXT:
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
    fws = [g.id for g in guides if g.kind == "framework"]
    topics = [g.id for g in guides if g.kind == "topic"]
    lines = ["# Detected stack", "",
             f"Languages: {', '.join(langs) or '-'}",
             f"Frameworks: {', '.join(fws) or '-'}",
             f"Topics: {', '.join(topics) or '-'}", ""]
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


def scaffold(target: str | Path, workspace: str | Path) -> ScaffoldResult:
    target = Path(target).resolve()
    project = target.name
    ws = Path(workspace) / project
    created: list[str] = []
    for sub in ("entrypoints", "issues", "analysis"):
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

    # detect the stack and seed its review guides (languages + frameworks)
    guides = select_guides(model.files, text=_detection_text(target, model.files))
    (ws / "_stack.md").write_text(_stack_md(guides), encoding="utf-8")

    # flag candidate entrypoint files via the matched guides' globs and by
    # scanning content for their entrypoint markers, for example a DRF ViewSet
    candidates = candidate_entrypoint_files(
        model.files, root=target,
        globs=entrypoint_globs(guides), markers=entrypoint_markers(guides),
    )
    (ws / "entrypoints" / "_entrypoints.md").write_text(_entrypoints_md(candidates), encoding="utf-8")

    return ScaffoldResult(
        project=project,
        workspace=ws,
        methodology=_METHODOLOGY.read_text(encoding="utf-8"),
        memory_path=memory_path,
        candidate_files=tuple(candidates),
        guides=tuple(g.id for g in guides),
        created=created,
    )
