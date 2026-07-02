"""Whole-repo review scaffold: set up the fan-out workspace, do not run a pipeline.

The `review repo` path. Whole-repo review is too large for a single LLM call and a
single pass over a large repo dilutes, so it ships as a methodology an interactive
agent runs by fanning out: it enumerates the attack surface, splits it into units,
and runs a focused sub-review on each. This module scaffolds the workspace for that
methodology: it creates the inventory/units/candidates/findings/pocs directories,
seeds the detected stack guides and the candidate entrypoint files, and returns the
methodology text to print. It does not find issues itself.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from codejury.detection import Detection, load_detection
from codejury.domains.base import Domain
from codejury.domains.registry import default_domain
from codejury.guides import (
    Guide,
    entrypoint_globs,
    entrypoint_markers,
    load_guides,
    logic_layer_globs,
    logic_unit_markers,
    select_guides,
)
from codejury.markdown_docs import iter_md_docs
from codejury.review.repo.model import (
    build_repo_model_from_dir,
    candidate_entrypoint_files,
    logic_layer_files,
    promoted_logic_units,
)

_DETECT_PER_FILE = 16_000
_DETECT_TOTAL = 8_000_000

_DIRS = ("inventory", "units", "candidates", "findings", "pocs")

# marks a directory as a codejury workspace, so a destructive --fresh clear never wipes an arbitrary directory
_MARKER = ".codejury-workspace"


@dataclass(frozen=True, kw_only=True)
class ScaffoldResult:
    project: str
    workspace: Path
    methodology: str
    candidate_files: tuple[str, ...] = ()
    logic_units: tuple[str, ...] = ()
    trace_targets: tuple[str, ...] = ()
    guides: tuple[str, ...] = ()
    created: list[str] = field(default_factory=list)
    had_prior_run: bool = False
    cleared: list[str] = field(default_factory=list)


def _read_manifests(target: Path, detection: Detection) -> str:
    parts: list[str] = []
    for name in detection.manifests:
        p = target / name
        try:
            if p.is_file():
                parts.append(p.read_text(encoding="utf-8"))
        except OSError:
            pass
    return "\n".join(parts)


def _source_sample(target: Path, files: list[str], detection: Detection) -> str:
    """A bounded sample of source and config content, so detection can fire on
    import markers and language-neutral content tokens such as a protocol's wire
    fields. Kept separate from the manifests so a dependency name does not
    false-match a word in source."""
    detection_extensions = detection.detection_extensions
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


# a schema tag in the cache key, so a change to the rendered facts shape invalidates every
# cached entry rather than serving a stale layout
_FACTS_SCHEMA = "1"


def _facts_cache_key(target: Path, files: tuple[str, ...], domain: Domain) -> str:
    """A content hash over the source in scope, so a re-run reuses the extracted facts
    instead of paying the slither pass again, while a source edit invalidates the entry."""
    h = hashlib.sha256()
    h.update(f"{_FACTS_SCHEMA}\x00{domain.name}".encode())
    for rel in sorted(files):
        try:
            data = (target / rel).read_bytes()
        except OSError:
            continue
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update(hashlib.sha256(data).digest())
    return h.hexdigest()


def _write_facts(ws: Path, target: Path, domain: Domain, files: tuple[str, ...], *,
                 enabled: bool, cache_root: Path, detection: Detection) -> None:
    """Extract deterministic facts and persist them to `_facts.md`, the way `_stack.md`
    persists the stack, so the run, resume, and finalize steps read the same grounding
    from the workspace. Facts are opt-in since extraction is heavy, the caller passes
    `enabled`. A domain may bind no backend or the toolchain may be absent, in which case
    the run falls back to its own heuristics. The extraction is cached by source content
    hash under `cache_root`, so a fresh scaffold or a second target on the same source
    reuses it rather than re-running the slither pass. A backend error is recorded to
    `_facts_error.txt` and the run continues without facts, never silently and never fatal
    to an otherwise reviewable repo."""
    if not enabled:
        return
    backend = domain.facts_backend
    if backend is None or not backend.available():
        return
    dest = ws / "_facts.md"
    dest_by_file = ws / "_facts_by_file.json"
    dest_units = ws / "_facts_units.json"
    if dest.is_file():
        # a prior scaffold already grounded this workspace, reuse it over re-extracting
        return
    error = ws / "_facts_error.txt"
    if error.exists():
        error.unlink()
    key = _facts_cache_key(target, files, domain)
    cached = cache_root / f"{key}.md"
    cached_by_file = cache_root / f"{key}.json"
    cached_units = cache_root / f"{key}.units.json"
    if cached.is_file():
        dest.write_text(cached.read_text(encoding="utf-8"), encoding="utf-8")
        if cached_by_file.is_file():
            dest_by_file.write_text(cached_by_file.read_text(encoding="utf-8"), encoding="utf-8")
        if cached_units.is_file():
            dest_units.write_text(cached_units.read_text(encoding="utf-8"), encoding="utf-8")
        return
    try:
        facts = backend.extract(target)
    except Exception as exc:
        error.write_text(f"facts extraction failed, the run falls back to heuristics: {exc}\n",
                         encoding="utf-8")
        return
    if not facts.empty:
        dest.write_text(facts.summary, encoding="utf-8")
        cache_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        cached.write_text(facts.summary, encoding="utf-8")
        # the per-file facts the engine grounds each unit with, so a large file's call graph
        # rides along whichever slice the unit reviews, see Facts.data["by_file"]
        by_file = facts.data.get("by_file") if isinstance(facts.data, dict) else None
        if by_file:
            payload = json.dumps(by_file)
            dest_by_file.write_text(payload, encoding="utf-8")
            cached_by_file.write_text(payload, encoding="utf-8")
        # the focused call-path units the engine adds to the worklist, see Facts.data["units"].
        # The facts backend compiles the whole project, tests included, so drop a unit packed
        # from a test or mock contract, the same test paths the candidate selection excludes,
        # so the call-path units never pull the review into test code
        units = facts.data.get("units") if isinstance(facts.data, dict) else None
        if units:
            units = [u for u in units
                     if not any(detection.is_test_path(str(f[0])) for f in u.get("fragments", []))]
        if units:
            payload = json.dumps(units)
            dest_units.write_text(payload, encoding="utf-8")
            cached_units.write_text(payload, encoding="utf-8")


_SURFACE_TEMPLATE = """\
# Attack Surface Inventory

Enumerate EVERY attacker-influenced entrypoint, one row each, grouped by module.
This is the coverage denominator: a unit you never list is a unit you never review.
See "Phase 1: Map the Attack Surface" in METHODOLOGY.md. The seeded entrypoints in
`_entrypoints.md` are a starting subset, not the whole surface, add non-HTTP sources
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

_INVARIANTS_TEMPLATE = """\
# Intent Invariants, Seeded by the Operator

Built once in Phase 1, every unit refers to this instead of guessing intent. The
operator who knows the business fills it. Each row a unit's code touches becomes a
property the unit must trace and try to break. See "Phase 1: Map the Attack Surface"
in METHODOLOGY.md. An invariant left blank seeds nothing, the unit reviews as before.

## Core Assets
<!-- What is valuable here and worth an attacker's effort: funds, balances, credits,
shares, votes, allowances, reputation, quota, a privileged seat. A static read sees
controls but not which state is the prize, so the operator names it. -->

## Who May Move Each Asset
<!-- For each asset, the only principals allowed to move or change it, and under what
condition. A reviewer can read who the code lets act, only the operator knows who
should be allowed, so the gap between them is where the finding lives. -->

## Invariants That Must Always Hold
<!-- The properties the operator asserts can never be violated, one row each, named by
the asset above. Pick the kind that fits. Conservation, total in equals total out and
nothing is minted from nothing. Single-use, a ticket, nonce, voucher, or vote spends
once. Monotonic, a balance, counter, or version only moves the allowed direction.
Ownership, only the owner of a resource mutates it. Ordering, a step happens only
after its prerequisite, create before approve before execute. State each as a property,
not a control, so a unit tests the property and does not just look for the named check. -->

| Asset | Invariant kind | The property in one line | Blast radius if it breaks |
|---|---|---|---|
<!-- Blast radius is the worst outcome if this property fails: funds drained, a vote
double-counted, a paid item taken free. It sets the floor severity for a unit that
finds the property breakable, so a real break is graded by this, never talked down. -->
"""


def _entrypoints_md(candidates: list[str], layers: list[str]) -> str:
    lines = ["# Seeded Entrypoints, a Starting Subset",
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
    # the .py strip is a legacy nicety, other extensions stay in the slug. The slug only has to
    # be unique and stable per path, so the inconsistency is cosmetic, not a collision risk
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
            f"calls, see `inventory/_entrypoints.md`\n\n---\n\n{mandate}")


def _has_prior_run(ws: Path) -> bool:
    """True when the workspace already holds a previous review's output, not just a
    bare scaffold. Seeded but un-reviewed units do not count, since the scaffold now
    seeds them. A reviewed unit, a finding, a PoC, or an edited surface does."""
    if not ws.exists():
        return False
    for sub in ("candidates", "findings", "pocs"):
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


def _refuse_legacy_layout(ws: Path) -> None:
    """A pre-split workspace kept proposals in issues/. Reading that as the new
    candidates/ would surface nothing, so refuse loud rather than report an empty
    review on stale state. Invariant 3."""
    issues = ws / "issues"
    candidates = ws / "candidates"
    legacy = issues.is_dir() and any(issues.iterdir())
    migrated = candidates.is_dir() and any(candidates.iterdir())
    if legacy and not migrated:
        raise ValueError(
            f"{ws} uses the old issues/ layout. Rename issues to candidates, or re-run "
            "with --fresh to discard prior state and start over."
        )


def _vulnerabilities_md(vulnerabilities_dir: Path) -> str:
    """Concatenate the shipped vulnerability class definitions into one seeded file, so the
    workspace carries the knowledge the methodology has each unit apply, rather than the
    agent working from memory. Same shape as the seeded stack notes."""
    parts = ["# Vulnerability Classes", "",
             "The shipped class definitions, each with vulnerable and secure examples. A unit "
             "applies the relevant ones to the code it reads, not from memory.", ""]
    for _path, _meta, body in iter_md_docs(vulnerabilities_dir):
        parts += ["---", "", body, ""]
    return "\n".join(parts) + "\n"


def scaffold(target: str | Path, workspace: str | Path, *, fresh: bool = False,
             domain: Domain | None = None, facts: bool = False) -> ScaffoldResult:
    dom = domain or default_domain()
    paths = dom.paths
    detection = load_detection(paths.detection_file)
    target = Path(target).resolve()
    project = target.name
    ws = Path(workspace) / project
    if not fresh:
        _refuse_legacy_layout(ws)
    had_prior_run = _has_prior_run(ws)
    cleared = _clear_prior_run(ws) if (fresh and ws.exists()) else []

    # the workspace holds the auth model, issue exploit paths, and PoCs, so keep it
    # private: 0700 on the workspace root and every directory under it, not the umask
    # default that leaves them world-readable on a shared host
    ws.mkdir(parents=True, exist_ok=True, mode=0o700)
    ws.chmod(0o700)
    (ws / _MARKER).write_text(f"{project}\n", encoding="utf-8")

    created: list[str] = []
    for sub in _DIRS:
        d = ws / sub
        if not d.exists():
            d.mkdir(parents=True, exist_ok=True, mode=0o700)
            created.append(str(d))

    model = build_repo_model_from_dir(target, detection)
    guides = select_guides(
        model.files,
        manifest_text=_read_manifests(target, detection),
        source_text=_source_sample(target, model.files, detection),
        guides=load_guides(paths.languages_dir, paths.frameworks_dir, paths.protocols_dir),
    )
    (ws / "_stack.md").write_text(_stack_md(guides), encoding="utf-8")
    _write_facts(ws, target, dom, model.files, enabled=facts,
                 cache_root=Path(workspace) / ".facts-cache", detection=detection)

    candidates = candidate_entrypoint_files(
        model.files, root=target,
        globs=entrypoint_globs(guides), markers=entrypoint_markers(guides), detection=detection,
    )
    layers = logic_layer_files(model.files, globs=logic_layer_globs(guides), detection=detection)
    # a logic-layer file that itself defines a security boundary is promoted to its own
    # unit, so its authorization check is reviewed by a dedicated sub-review rather than
    # only traced into from a route, where a generic-CRUD framework hides the decision.
    promoted = promoted_logic_units(
        model.files, root=target,
        layer_globs=logic_layer_globs(guides), markers=logic_unit_markers(guides), detection=detection,
    )
    promoted_set = set(promoted)
    layers = [f for f in layers if f not in promoted_set]
    unit_files = sorted(dict.fromkeys([*candidates, *promoted]))
    (ws / "inventory" / "_entrypoints.md").write_text(_entrypoints_md(candidates, layers), encoding="utf-8")

    # generate the deterministic unit worklist: one unit per candidate entrypoint,
    # each carrying the same fixed deep-review mandate. Code owns the worklist and
    # the depth mandate. The agent fans out one sub-review per unit, it does not
    # decide the units, whether to fan out, or how deep to go. Never clobber a unit
    # an earlier run already wrote.
    mandate = paths.unit_review_file.read_text(encoding="utf-8")
    for cand in unit_files:
        up = ws / "units" / f"{unit_slug(cand)}.md"
        if not up.exists():
            up.write_text(_unit_md(cand, mandate), encoding="utf-8")
            created.append(str(up))

    # seed the denominator and the auth-model templates the agent fills in Phase 1,
    # never clobber an edited one
    for name, template in (("_surface.md", _SURFACE_TEMPLATE), ("_auth_model.md", _AUTH_MODEL_TEMPLATE),
                           ("_invariants.md", _INVARIANTS_TEMPLATE)):
        p = ws / "inventory" / name
        if not p.exists():
            p.write_text(template, encoding="utf-8")
            created.append(str(p))

    sev = ws / "inventory" / "_severity.md"
    if not sev.exists():
        sev.write_text(paths.severity_rubric_file.read_text(encoding="utf-8"), encoding="utf-8")
        created.append(str(sev))

    (ws / "_false_positive_traps.md").write_text(
        paths.false_positive_traps_file.read_text(encoding="utf-8"), encoding="utf-8")

    (ws / "_vulnerabilities.md").write_text(_vulnerabilities_md(paths.vulnerabilities_dir), encoding="utf-8")

    return ScaffoldResult(
        project=project,
        workspace=ws,
        methodology=paths.methodology_file.read_text(encoding="utf-8"),
        candidate_files=tuple(candidates),
        logic_units=tuple(promoted),
        trace_targets=tuple(layers),
        guides=tuple(g.id for g in guides),
        created=created,
        had_prior_run=had_prior_run,
        cleared=cleared,
    )
