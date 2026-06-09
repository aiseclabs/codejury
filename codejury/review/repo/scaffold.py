"""Whole-repo review scaffold: set up the fan-out workspace, do not run a pipeline.

The `review repo` path. Whole-repo review is too large for a single LLM call and a
single pass over a large repo dilutes, so it ships as a methodology an interactive
agent runs by fanning out: it enumerates the attack surface, splits it into units,
and runs a focused sub-review on each. This module scaffolds the workspace for that
methodology: it creates the inventory/units/issues/pocs directories, seeds the
detected stack guides and the candidate entrypoint files, and returns the
methodology text to print. It does not find issues itself.
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
from codejury.markdown_docs import iter_md_docs
from codejury.review.repo.model import build_repo_model_from_dir, candidate_entrypoint_files, logic_layer_files
from codejury.resources import (
    FALSE_POSITIVE_TRAPS_FILE,
    METHODOLOGY_FILE,
    SEVERITY_RUBRIC_FILE,
    UNIT_REVIEW_FILE,
    VULNERABILITIES_DIR,
)

_DETECT_PER_FILE = 16_000   # bytes read per file
_DETECT_TOTAL = 8_000_000   # bytes of source sampled overall

# the workspace directories the fan-out methodology writes into
_DIRS = ("inventory", "units", "issues", "pocs")

# a marker file written at the project workspace root, so a destructive --fresh clear can
# tell a codejury workspace from an arbitrary directory it must never wipe
_MARKER = ".codejury-workspace"


@dataclass(frozen=True, kw_only=True)
class ScaffoldResult:
    project: str
    workspace: Path
    methodology: str
    candidate_files: tuple[str, ...] = ()   # files a matched guide flags as likely entrypoints
    trace_targets: tuple[str, ...] = ()     # downstream logic-layer files to trace into
    guides: tuple[str, ...] = ()
    created: list[str] = field(default_factory=list)
    had_prior_run: bool = False
    cleared: list[str] = field(default_factory=list)


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
    false-match a word in source."""
    detection_extensions = load_detection().detection_extensions
    parts: list[str] = []
    total = 0
    for f in files:
        if Path(f).suffix.lower() not in detection_extensions:
            continue
        try:
            chunk = (target / f).read_text(encoding="utf-8")[:_DETECT_PER_FILE]
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
    fw_labels = [f"{g.id} ({g.language})" if g.language else g.id for g in fws]
    lines = ["# Detected stack", "",
             f"Languages: {', '.join(langs) or '-'}",
             f"Frameworks: {', '.join(fw_labels) or '-'}",
             f"Protocols: {', '.join(protocols) or '-'}", ""]
    for g in guides:
        lines += ["---", "", g.body, ""]
    return "\n".join(lines) + "\n"


_SURFACE_TEMPLATE = """\
# Attack Surface Inventory

Enumerate EVERY attacker-influenced entrypoint, one row each, grouped by module.
This is the coverage denominator: a unit you never list is a unit you never review.
See "Phase 1: Map the Attack Surface" in METHODOLOGY.md. The seeded candidates in
`_candidates.md` are a starting subset, not the whole surface, add non-HTTP sources
such as deserializers, queue consumers, and file parsers.

Status legend: `open` not assigned to a unit yet, `assigned` assigned to a unit in `units/`.

| Module | Entrypoint, METHOD path or non-HTTP source | Auth method | Unit | Status |
|---|---|---|---|---|
"""

_AUTH_MODEL_TEMPLATE = """\
# Authorization Model, Trust Boundaries, Sensitive Data

Built once in Phase 1, every unit refers to this instead of re-deriving it. See
"Phase 1: Map the Attack Surface" in METHODOLOGY.md.

## Access control mechanism
<!-- How this codebase authenticates a caller and authorizes a resource: the
decorator, middleware, permission class, signature, or guard, and where it lives. -->

## Actors and trust boundaries
<!-- The users, tenants, services, and the boundaries between them. Which callers
distrust which. Once adopted, grade every finding on the same boundary the same way. -->

## Sensitive data map
<!-- Where tokens, secrets, PII, keys, and other tenants' data live, since the
data-exposure class has no attacker entrypoint and an entrypoint read misses it. -->
"""


def _candidates_md(candidates: list[str], layers: list[str]) -> str:
    lines = ["# Seeded Candidates, a Starting Subset",
             "",
             "Files the detected stack flags as likely to define entrypoints, and the",
             "downstream logic-layer files to trace into. A starting point for the",
             "Phase 1 surface map and the Phase 2 traces, not the whole surface.",
             "",
             "## Candidate entrypoint files", ""]
    lines += [f"- {f}" for f in candidates] or ["(none flagged, enumerate by reading the code)"]
    lines += ["", "## Downstream logic layers to trace into", ""]
    lines += [f"- {f}" for f in layers] or ["(none flagged, follow the calls out of each entrypoint)"]
    return "\n".join(lines) + "\n"


def unit_slug(path: str) -> str:
    """The slug a unit file is named by, derived from the path it owns. Public so the
    engine can recompute the same name when resuming, instead of reaching for a private."""
    s = path.replace("\\", "/").removesuffix(".py")
    return "".join(c if c.isalnum() else "-" for c in s).strip("-").lower() or "unit"


def _unit_md(owned: str, mandate: str) -> str:
    """A seeded unit: the code path it owns plus the fixed deep-review mandate, the
    same mandate for every unit so per-unit depth does not vary with the agent's
    mood. The orchestrator spawns one sub-review per unit file, it does not decide
    the units or the depth."""
    return (f"# Unit: {owned}\n\n"
            f"- Status: open\n"
            f"- Owns: `{owned}`\n"
            f"- Trace into: the managers, controllers, dao, and libraries this file "
            f"calls, see `inventory/_candidates.md`\n\n---\n\n{mandate}")


def _has_prior_run(ws: Path) -> bool:
    """True when the workspace already holds a previous review's output, not just a
    bare scaffold. Seeded but un-reviewed units do not count, since the scaffold now
    seeds them. A reviewed unit, a finding, a PoC, or an edited surface does."""
    if not ws.exists():
        return False
    for sub in ("issues", "pocs"):
        d = ws / sub
        if d.is_dir() and any(d.iterdir()):
            return True
    units = ws / "units"
    if units.is_dir() and any(
        "status: reviewed" in u.read_text(encoding="utf-8").lower() for u in units.glob("*.md")
    ):
        return True
    surface = ws / "inventory" / "_surface.md"
    return surface.exists() and surface.read_text(encoding="utf-8") != _SURFACE_TEMPLATE


def _clear_prior_run(ws: Path) -> list[str]:
    """Remove a previous review's output so a fresh run starts clean, so no stale
    judgment suppresses a finding. Refuse to wipe a non-empty directory that is not a
    codejury workspace: --workspace is arbitrary and a target name such as `api` or
    `app` is common, so a marker check stops --fresh deleting unrelated data."""
    if any(ws.iterdir()) and not (ws / _MARKER).is_file():
        raise ValueError(
            f"{ws} is not empty and has no {_MARKER} marker, so it does not look like a "
            "codejury workspace. Refusing to clear it. Choose another --workspace or "
            "remove the directory by hand."
        )
    removed: list[str] = []
    for child in ws.iterdir():
        shutil.rmtree(child) if child.is_dir() else child.unlink()
        removed.append(str(child))
    return removed


def _vulnerabilities_md() -> str:
    """Concatenate the shipped vulnerability class definitions into one seeded file, so the
    workspace carries the knowledge the methodology has each unit apply, rather than the
    agent working from memory. Same shape as the seeded stack notes."""
    parts = ["# Vulnerability Classes", "",
             "The shipped class definitions, each with vulnerable and secure examples. A unit "
             "applies the relevant ones to the code it reads, not from memory.", ""]
    for _path, _meta, body in iter_md_docs(VULNERABILITIES_DIR):
        parts += ["---", "", body, ""]
    return "\n".join(parts) + "\n"


def scaffold(target: str | Path, workspace: str | Path, *, fresh: bool = False) -> ScaffoldResult:
    target = Path(target).resolve()
    project = target.name
    ws = Path(workspace) / project
    had_prior_run = _has_prior_run(ws)
    cleared = _clear_prior_run(ws) if (fresh and ws.exists()) else []

    # the workspace holds the auth model, issue exploit paths, and PoCs, so keep it
    # private: 0700 on the workspace root and every directory under it, not the umask
    # default that leaves them world-readable on a shared host
    ws.mkdir(parents=True, exist_ok=True, mode=0o700)
    ws.chmod(0o700)   # tighten an existing workspace too, mkdir's mode is ignored when it exists
    (ws / _MARKER).write_text(f"{project}\n", encoding="utf-8")

    created: list[str] = []
    for sub in _DIRS:
        d = ws / sub
        if not d.exists():
            d.mkdir(parents=True, exist_ok=True, mode=0o700)
            created.append(str(d))

    model = build_repo_model_from_dir(target)
    guides = select_guides(
        model.files,
        manifest_text=_read_manifests(target),
        source_text=_source_sample(target, model.files),
    )
    (ws / "_stack.md").write_text(_stack_md(guides), encoding="utf-8")

    candidates = candidate_entrypoint_files(
        model.files, root=target,
        globs=entrypoint_globs(guides), markers=entrypoint_markers(guides),
    )
    layers = logic_layer_files(model.files, globs=logic_layer_globs(guides))
    (ws / "inventory" / "_candidates.md").write_text(_candidates_md(candidates, layers), encoding="utf-8")

    # generate the deterministic unit worklist: one unit per candidate entrypoint,
    # each carrying the same fixed deep-review mandate. Code owns the worklist and
    # the depth mandate. The agent fans out one sub-review per unit, it does not
    # decide the units, whether to fan out, or how deep to go. Never clobber a unit
    # an earlier run already wrote.
    mandate = UNIT_REVIEW_FILE.read_text(encoding="utf-8")
    for cand in candidates:
        up = ws / "units" / f"{unit_slug(cand)}.md"
        if not up.exists():
            up.write_text(_unit_md(cand, mandate), encoding="utf-8")
            created.append(str(up))

    # seed the denominator and the auth-model templates the agent fills in Phase 1,
    # never clobber an edited one
    for name, template in (("_surface.md", _SURFACE_TEMPLATE), ("_auth_model.md", _AUTH_MODEL_TEMPLATE)):
        p = ws / "inventory" / name
        if not p.exists():
            p.write_text(template, encoding="utf-8")
            created.append(str(p))

    # seed the severity rubric the units grade against, so every severity is surfaced
    # by one shared standard, never refuted away for low impact
    sev = ws / "inventory" / "_severity.md"
    if not sev.exists():
        sev.write_text(SEVERITY_RUBRIC_FILE.read_text(encoding="utf-8"), encoding="utf-8")
        created.append(str(sev))

    # seed the recurring false-positive traps the verification step refutes against
    (ws / "_false_positive_traps.md").write_text(
        FALSE_POSITIVE_TRAPS_FILE.read_text(encoding="utf-8"), encoding="utf-8")

    # seed the vulnerability class definitions the methodology has each unit apply
    (ws / "_vulnerabilities.md").write_text(_vulnerabilities_md(), encoding="utf-8")

    return ScaffoldResult(
        project=project,
        workspace=ws,
        methodology=METHODOLOGY_FILE.read_text(encoding="utf-8"),
        candidate_files=tuple(candidates),
        trace_targets=tuple(layers),
        guides=tuple(g.id for g in guides),
        created=created,
        had_prior_run=had_prior_run,
        cleared=cleared,
    )
