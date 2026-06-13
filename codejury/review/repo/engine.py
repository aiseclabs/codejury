"""Run the coded multi-pass repo-review engine end to end.

The library entry behind `review repo --run`. It scaffolds the workspace, builds the
unit worklist from the seeded candidates, runs the deterministic pass-loop with a
model-backed reviewer until the union converges, then writes the findings into the
workspace and marks every unit reviewed. The orchestration is fully coded, so a run
covers every unit every pass and stops on convergence, not on the agent's whim.

Recall is the union across diverse passes. Precision is tightened by a later
verification stage. Findings are written both as `findings/*.md` and a
machine-readable `findings.json`, so a run can be scored against an answer key.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path

from codejury.detection import load_detection
from codejury.domains.base import ContentPaths, Domain
from codejury.domains.registry import default_domain
from codejury.markdown_docs import md_field
from codejury.providers.base import Provider
from codejury.review.repo.paths import is_unsafe_rel, safe_repo_path
from codejury.review.repo.pass_loop import run_passes
from codejury.review.repo.reviewer import ModelReviewer, Unit, UnitReviewer
from codejury.review.repo.scaffold import ScaffoldResult, scaffold, unit_slug
from codejury.review.repo.severity import calibrated, median
from codejury.review.repo.union import Accumulator, Candidate, collapse_colocated, merge
from codejury.review.repo.verifier import ModelVerifier, VerifyResult, Verifier, verify_findings

_MAX_RELATED = 20
# a file longer than this many chars is reviewed in overlapping windows, not truncated
_CHUNK_CHARS = 24_000
_CHUNK_OVERLAP = 2_000


def _finding_slug(text: str) -> str:
    return ("".join(c if c.isalnum() else "-" for c in text).strip("-").lower() or "finding")[:80]


def _file_text(root: str, rel: str) -> str:
    path = safe_repo_path(root, rel)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def _construct_boundaries(text: str) -> list[int]:
    """Char indices where a line begins with a non-space character, the start of a
    top-level construct in an indented language such as Python, Go, or JavaScript. Window
    edges snap to these so a class or function is reviewed whole, not split across units."""
    starts: list[int] = []
    at_line_start = True
    for i, ch in enumerate(text):
        if at_line_start and not ch.isspace():
            starts.append(i)
        at_line_start = ch == "\n"
    return starts


def _spans(text: str) -> list[tuple[int, int] | None]:
    """The char windows that cover `text`. Text that fits one call is reviewed whole, span
    None. Larger text is split at top-level construct boundaries so each class or function
    lands whole in one window. A single construct longer than a window is hard split with
    an overlap, so even then no boundary silently drops a construct's tail."""
    size = len(text)
    if size <= _CHUNK_CHARS:
        return [None]
    boundaries = _construct_boundaries(text)
    spans: list[tuple[int, int] | None] = []
    start = 0
    while True:
        target = start + _CHUNK_CHARS
        if target >= size:
            spans.append((start, size))
            return spans
        within = [b for b in boundaries if start < b <= target]
        if within:
            # end at the furthest construct boundary in the window, so it splits cleanly
            end = within[-1]
            next_start = end
        else:
            # one construct is longer than a window, hard split it with an overlap
            end = target
            next_start = end - _CHUNK_OVERLAP
        spans.append((start, end))
        start = next_start


def build_units(root: str | Path, candidate_files, trace_targets) -> list[Unit]:
    """One unit per candidate entrypoint, packed with the trace-target files that share its
    top-level package, so a single review call can trace across them. A candidate too large
    for one call is split into several units over overlapping char windows, so the whole
    file is covered rather than truncated to its head."""
    root = str(root)
    targets = list(trace_targets)
    units: list[Unit] = []
    for cand in candidate_files:
        pkg = Path(cand).parts[0] if Path(cand).parts else ""
        related = tuple(t for t in targets if Path(t).parts and Path(t).parts[0] == pkg)[:_MAX_RELATED]
        spans = _spans(_file_text(root, cand))
        if len(spans) == 1:
            units.append(Unit(name=cand, root=root, files=(cand, *related)))
            continue
        for i, span in enumerate(spans):
            units.append(Unit(name=f"{cand}#{i + 1}", root=root, files=(cand, *related), span=span))
    return units


def _finding_md(c: Candidate) -> str:
    src = c.endpoint or c.file or "(no location)"
    return (f"# {c.title}\n\n"
            f"- Risk: {c.severity}\n"
            f"- Type: {c.category or 'other'}\n"
            f"- Source: `{src}`\n"
            f"- Status: {c.status}\n\n"
            f"## Analysis\n{c.evidence or '(see code)'}\n")


def _finding_name(c: Candidate) -> str:
    """The shared name tying a finding to its source candidate and its poc. In the agent
    flow the candidate file basename is that name, carried on the candidate in evidence.
    The coded run has no candidate file, so fall back to the finding slug."""
    if c.evidence.endswith(".md"):
        return Path(c.evidence).stem
    return _finding_slug(c.endpoint or c.title)


def _poc_for(ws: Path, name: str) -> str:
    """The poc whose basename matches a finding's name, the link the methodology asks
    the agent to keep by naming candidates/<name>.md and pocs/<name>.<ext> alike."""
    pocs = ws / "pocs"
    if not pocs.is_dir():
        return ""
    for p in sorted(pocs.iterdir()):
        if p.is_file() and p.stem == name:
            return f"pocs/{p.name}"
    return ""


def _finding_entry(ws: Path, c: Candidate) -> dict:
    candidate = f"candidates/{c.evidence}" if c.evidence.endswith(".md") else ""
    return {"title": c.title, "category": c.category, "entry": c.endpoint,
            "file": c.file, "line": c.line, "severity": c.severity, "status": c.status,
            "candidate": candidate, "poc": _poc_for(ws, _finding_name(c))}


def _write_findings(ws: Path, findings: list[Candidate]) -> None:
    """Write the confirmed findings, the code-owned output. findings/ is cleared and
    rewritten in full, so a shrunk or refuted set leaves no stale file behind, and the
    agent's candidates/ and pocs/ are never touched."""
    findings_dir = ws / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    for p in findings_dir.glob("*.md"):
        p.unlink()
    for c in findings:
        (findings_dir / f"{_finding_name(c)}.md").write_text(_finding_md(c), encoding="utf-8")
    (ws / "findings.json").write_text(json.dumps(
        {"findings": [_finding_entry(ws, c) for c in findings]}, indent=2, ensure_ascii=False),
        encoding="utf-8")


def _write_pocs_report(ws: Path, findings: list[Candidate]) -> None:
    """Reconcile pocs/ against the confirmed findings, recorded not enforced: a finding
    may need a PoC only an operator can run, invariant 4, and a PoC may outlive a
    candidate the verifier later refuted. Surface both so neither is silently lost."""
    pocs = ws / "pocs"
    poc_files = sorted(p for p in pocs.iterdir() if p.is_file()) if pocs.is_dir() else []
    if not poc_files and not any(c.evidence.endswith(".md") for c in findings):
        # the coded run produces findings with no agent candidates or pocs, so there is
        # nothing to reconcile, skip rather than list every finding as missing a poc
        return
    names = {_finding_name(c) for c in findings}
    poc_names = {p.stem for p in poc_files}
    missing = [c for c in findings if _finding_name(c) not in poc_names]
    orphan = [p for p in poc_files if p.stem not in names]
    lines = ["# PoC Reconciliation", "",
             "Confirmed findings matched to PoCs by name. Recorded, not gated: a finding "
             "may need a PoC only an operator can run, and a PoC may outlive a refuted candidate.",
             "", "## Confirmed findings with no PoC", ""]
    lines += [f"- **{c.title}** `{c.endpoint or c.file}`" for c in missing] or ["None, every confirmed finding has a PoC."]
    lines += ["", "## PoC files with no confirmed finding", ""]
    lines += [f"- `pocs/{p.name}`" for p in orphan] or ["None, every PoC maps to a confirmed finding."]
    (ws / "_pocs.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_surface(ws: Path, units: list[Unit], failed: set) -> None:
    """Populate the attack-surface inventory from the unit worklist: in a coded run
    the enumerated surface IS the worklist, one row per unit, so the denominator is
    explicit and the gate's surface check is satisfied. A unit that never reviewed
    cleanly this run is marked open, not reviewed, so the surface does not claim a
    failed unit was covered."""
    lines = ["# Attack Surface Inventory", "",
             "Enumerated by the coded engine from the unit worklist, one row per unit.", "",
             "| Package | Entrypoint file | Unit | Status |", "|---|---|---|---|"]
    for u in units:
        owned = u.files[0] if u.files else u.name
        pkg = Path(owned).parts[0] if Path(owned).parts else ""
        status = "open" if u.name in failed else "reviewed"
        lines.append(f"| {pkg} | {owned} | {u.name} | {status} |")
    (ws / "inventory" / "_surface.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_refuted(ws: Path, refuted: list[tuple[Candidate, str]]) -> None:
    """Record what the verifier dropped, so a refutation is auditable, not invisible."""
    lines = ["# Refuted candidates", "",
             "Surfaced by a review pass, then refuted by the adversarial verifier on a "
             "named controlling fact. Recorded so a wrong refutation is visible.", ""]
    for c, reason in refuted:
        lines.append(f"- **{c.title}** ({c.severity} {c.category}) `{c.endpoint or c.file}`: {reason}")
    (ws / "_refuted.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _mark_units_reviewed(ws: Path, reviewed_slugs: set) -> None:
    """Flip a unit from open to reviewed only when it reviewed cleanly this run. A unit
    that raised on every pass is left open, so the gate catches it and a later resume
    retries it, never reporting a failed review as covered."""
    for u in (ws / "units").glob("*.md"):
        if u.stem not in reviewed_slugs:
            continue
        text = u.read_text(encoding="utf-8")
        u.write_text(re.sub(r"(?im)^-\s*Status:\s*open\s*$", "- Status: reviewed", text), encoding="utf-8")


def _cand_to_dict(c: Candidate) -> dict:
    return {"title": c.title, "category": c.category, "endpoint": c.endpoint, "file": c.file,
            "line": c.line, "severity": c.severity, "evidence": c.evidence, "status": c.status}


def _cand_from_dict(d: dict) -> Candidate:
    return Candidate(title=d.get("title", ""), category=d.get("category", ""),
                     endpoint=d.get("endpoint", ""), file=d.get("file", ""), line=d.get("line"),
                     severity=d.get("severity", "MEDIUM"), evidence=d.get("evidence", ""),
                     status=d.get("status", "confirmed"))


def _keystr(c: Candidate) -> str:
    return "|".join(str(p) for p in c.key())


def _save_union(ws: Path, cands: list[Candidate]) -> None:
    (ws / "_union.json").write_text(
        json.dumps({"findings": [_cand_to_dict(c) for c in cands]}, indent=2, ensure_ascii=False),
        encoding="utf-8")


def _resume_corrupt(p: Path, exc: Exception) -> ValueError:
    # a present-but-corrupt checkpoint must fail loud, never fall back to an empty pool:
    # on a resume the units are already reviewed, so an empty pool would write a zero
    # finding report and exit clean, hiding the lost progress. Invariant 3.
    return ValueError(
        f"resume checkpoint {p} is unreadable or corrupt: {exc}. "
        "Re-run with --fresh to discard prior state and start over."
    )


def _load_union(ws: Path) -> dict:
    p = ws / "_union.json"
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise _resume_corrupt(p, exc) from exc
    pool: dict = {}
    for d in data.get("findings", []):
        c = _cand_from_dict(d)
        pool[c.key()] = c
    return pool


def _load_verified(ws: Path) -> dict:
    p = ws / "_verified.json"
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise _resume_corrupt(p, exc) from exc


def _save_verified(ws: Path, verified: dict) -> None:
    (ws / "_verified.json").write_text(json.dumps(verified, indent=2, ensure_ascii=False), encoding="utf-8")


def _reviewed_slugs(ws: Path) -> set:
    return {u.stem for u in (ws / "units").glob("*.md")
            if re.search(r"(?im)^-\s*Status:\s*reviewed\s*$", u.read_text(encoding="utf-8"))}


def apply_verification(
    ws: Path,
    findings: list[Candidate],
    *,
    root: str,
    verifier: Verifier | None,
    provider: Provider | None,
    model: str,
    votes: int,
    concurrency: int,
    fresh: bool,
    content: ContentPaths | None = None,
) -> tuple[list[Candidate], VerifyResult]:
    """Adversarially verify a finding list, resumable via `_verified.json`, and record
    the refuted. The single home for the verify step the coded run and the finalize pass
    both share, so a change to the cache format or the refuted output cannot drift
    between them. A finding already verified is not re-verified, and on fresh the cache
    is ignored. A failed verification is counted in the result and the finding is kept,
    never silently dropped, invariant 3."""
    if verifier is None:
        if provider is None:
            raise ValueError("verification needs a provider, or an injected verifier")
        verifier = ModelVerifier(provider=provider, model=model, content=content)
    verified = {} if fresh else _load_verified(ws)
    to_verify = [c for c in findings if _keystr(c) not in verified]
    new_vr = verify_findings(to_verify, verifier, root, votes=votes, concurrency=concurrency)
    for c in new_vr.confirmed:
        verified[_keystr(c)] = {"real": True, "reason": ""}
    for c, reason in new_vr.refuted:
        verified[_keystr(c)] = {"real": False, "reason": reason}
    _save_verified(ws, verified)
    confirmed = [c for c in findings if verified.get(_keystr(c), {"real": True})["real"]]
    refuted = [(c, verified[_keystr(c)]["reason"]) for c in findings
               if not verified.get(_keystr(c), {"real": True})["real"]]
    _write_refuted(ws, refuted)
    return confirmed, VerifyResult(confirmed=confirmed, refuted=refuted, errors=new_vr.errors)


def _md_field(text: str, key: str) -> str:
    v = md_field(text, key)
    return v.strip("`").strip() if v is not None else ""


@lru_cache(maxsize=None)
def _location_re(source_extensions: frozenset[str]) -> re.Pattern:
    """The location matcher, built from the data-driven source extensions so no
    language is named in code. Extensions are sorted longest first so a path like
    `app.tsx` matches the `tsx` alternative, not the `ts` prefix of it. Cached per
    extension set so each domain's matcher is built once."""
    exts = sorted((e.lstrip(".") for e in source_extensions), key=len, reverse=True)
    alt = "|".join(re.escape(e) for e in exts)
    return re.compile(rf"([\w./-]+\.(?:{alt}))(?::(\d+))?")


def _parse_candidate(path: Path, source_extensions: frozenset[str] | None = None) -> Candidate | None:
    """Parse an agent-written candidates/<name>.md into a Candidate for coded dedup and
    verification, so those steps do not depend on the agent's prose. The source
    extensions decide what counts as a file location, defaulting to the web domain."""
    if source_extensions is None:
        source_extensions = load_detection().source_extensions
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    title = next((ln[2:].strip() for ln in text.splitlines() if ln.startswith("# ")), path.stem)
    sev_raw = _md_field(text, "(?:risk|severity)").upper()
    severity = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if s in sev_raw), "MEDIUM")
    fm = _location_re(source_extensions).search(text)
    if fm is None or is_unsafe_rel(fm.group(1)):
        # invariant 2: with no file location the issue is not reportable. An absolute or
        # parent-traversing path is not a location inside the repo, a tampered or
        # hallucinated issue file, so it is dropped, not read.
        return None
    status_raw = _md_field(text, "status").lower()
    return Candidate(
        title=title or path.stem,
        category=_md_field(text, "type"),
        endpoint=_md_field(text, "source"),
        file=fm.group(1),
        line=int(fm.group(2)) if fm.group(2) else None,
        severity=severity,
        evidence=path.name,
        status="blocked" if status_raw == "blocked" else "confirmed",
    )


@dataclass(frozen=True, kw_only=True)
class FinalizeResult:
    workspace: Path
    parsed: int
    deduped: int
    verify: VerifyResult | None


def finalize_repo_review(
    target: str | Path,
    workspace: str | Path,
    *,
    verifier: Verifier | None = None,
    provider: Provider | None = None,
    model: str = "",
    verify: bool = True,
    votes: int = 1,
    concurrency: int = 6,
    domain: Domain | None = None,
) -> FinalizeResult:
    """The coded post-fan-out pipeline: dedup, verify, report over the agent's candidates.

    These steps are mechanical, so they are code, not agent prose: it reads
    `candidates/*.md`, dedups by location and class, adversarially verifies each survivor,
    resumable and skipping any already in `_verified.json`, drops the refuted into
    `_refuted.md`, and writes the confirmed `findings/*.md` and the ranked `findings.json`."""
    paths = (domain or default_domain()).paths
    source_extensions = load_detection(paths.detection_file).source_extensions
    ws = Path(workspace) / Path(target).resolve().name
    root = str(Path(target).resolve())

    cands = [c for c in (_parse_candidate(p, source_extensions) for p in sorted((ws / "candidates").glob("*.md"))) if c]
    sev_votes: dict = {}
    for c in cands:
        sev_votes.setdefault(c.key(), []).append(c.severity)
    pool: dict = {}
    merge(pool, cands)
    deduped = [
        replace(c, severity=calibrated(median(sev_votes.get(c.key(), [c.severity])), c.category, c.title))
        for c in collapse_colocated(list(pool.values()))
    ]

    vr: VerifyResult | None = None
    if verify and deduped:
        deduped, vr = apply_verification(
            ws, deduped, root=root, verifier=verifier, provider=provider, model=model,
            votes=votes, concurrency=concurrency, fresh=False, content=paths,
        )

    _write_findings(ws, deduped)
    _write_pocs_report(ws, deduped)
    return FinalizeResult(workspace=ws, parsed=len(cands), deduped=len(deduped), verify=vr)


@dataclass(frozen=True, kw_only=True)
class RunResult:
    scaffold: ScaffoldResult
    accumulator: Accumulator
    units: int
    verify: VerifyResult | None = None


def run_repo_review(
    target: str | Path,
    workspace: str | Path,
    *,
    provider: Provider | None = None,
    model: str = "",
    reviewer: UnitReviewer | None = None,
    verifier: Verifier | None = None,
    verify: bool = True,
    votes: int = 1,
    max_passes: int = 24,
    converge_after: int = 2,
    concurrency: int = 6,
    fresh: bool = False,
    on_pass=None,
    domain: Domain | None = None,
) -> RunResult:
    domain = domain or default_domain()
    paths = domain.paths
    root = str(Path(target).resolve())
    res = scaffold(target, workspace, fresh=fresh, domain=domain)
    ws = res.workspace
    units = build_units(root, res.candidate_files, res.trace_targets)
    if not units:
        # zero units means the stack detection flagged no entrypoint, so a run would
        # review nothing and still look clean. Fail loud, invariant 3: a review that
        # covered nothing is not a clean pass. The operator scaffolds and seeds the
        # candidates by hand, or adds a guide for the stack, then re-runs.
        raise ValueError(
            f"no candidate entrypoints detected under {root}, so there is nothing to "
            "review. Add a guide for this stack or seed inventory/_entrypoints.md, then re-run."
        )

    reviewed = set() if fresh else _reviewed_slugs(ws)
    open_units = [u for u in units if unit_slug(u.name) not in reviewed]
    acc = Accumulator(converge_after=converge_after, pool=({} if fresh else _load_union(ws)))

    shared = (ws / "_stack.md").read_text(encoding="utf-8")
    if reviewer is None:
        if provider is None:
            raise ValueError("run_repo_review needs a provider, or an injected reviewer")
        reviewer = ModelReviewer(provider=provider, model=model, content=paths)

    run_passes(
        open_units, reviewer,
        converge_after=converge_after, max_passes=max_passes,
        shared_context=shared, concurrency=concurrency, on_pass=on_pass,
        persist=lambda f: _save_union(ws, f), accumulator=acc,
    )
    _save_union(ws, acc.findings)
    reviewed_slugs = {unit_slug(u.name) for u in open_units if u.name not in acc.failed_units}
    _mark_units_reviewed(ws, reviewed_slugs)

    findings = acc.findings
    vr: VerifyResult | None = None
    if verify:
        findings, vr = apply_verification(
            ws, findings, root=root, verifier=verifier, provider=provider, model=model,
            votes=votes, concurrency=concurrency, fresh=fresh, content=paths,
        )

    _write_surface(ws, units, acc.failed_units)
    _write_findings(ws, findings)
    _write_pocs_report(ws, findings)
    return RunResult(scaffold=res, accumulator=acc, units=len(units), verify=vr)
