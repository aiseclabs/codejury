"""Run the coded multi-pass repo-review engine end to end.

The library entry behind `review repo --run`. It scaffolds the workspace, builds the
unit worklist from the seeded candidates, runs the deterministic pass-loop with a
model-backed reviewer until the union converges, then writes the findings into the
workspace and marks every unit reviewed. The orchestration is fully coded, so a run
covers every unit every pass and stops on convergence, not on the agent's whim.

Recall is the union across diverse passes; precision is tightened by a later
verification stage (not yet wired). Findings are written both as `issues/*.md` and a
machine-readable `findings.json`, so a run can be scored against an answer key.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from pathlib import Path

from codejury.providers.base import Provider
from codejury.review.repo.passloop import run_passes
from codejury.review.repo.reviewer import ModelReviewer, Unit, UnitReviewer
from codejury.review.repo.scaffold import ScaffoldResult, scaffold
from codejury.review.repo.scaffold import _slug as _unit_slug   # the slug the scaffold names unit files by
from codejury.review.repo.severity import calibrated, median
from codejury.review.repo.union import Accumulator, Candidate, collapse_colocated, merge
from codejury.review.repo.verifier import ModelVerifier, VerifyResult, Verifier, verify_findings

_MAX_RELATED = 20   # trace-target files packed into a unit beyond the owned file


def _slug(text: str) -> str:
    return ("".join(c if c.isalnum() else "-" for c in text).strip("-").lower() or "finding")[:80]


def build_units(root: str | Path, candidate_files, trace_targets) -> list[Unit]:
    """One unit per candidate entrypoint, packed with the trace-target files that
    share its top-level package, so a single review call can trace across them."""
    root = str(root)
    targets = list(trace_targets)
    units: list[Unit] = []
    for cand in candidate_files:
        pkg = Path(cand).parts[0] if Path(cand).parts else ""
        related = tuple(t for t in targets if Path(t).parts and Path(t).parts[0] == pkg)[:_MAX_RELATED]
        units.append(Unit(name=cand, root=root, files=(cand, *related)))
    return units


def _issue_md(c: Candidate) -> str:
    src = c.endpoint or c.file or "(no location)"
    return (f"# {c.title}\n\n"
            f"- Risk: {c.severity}\n"
            f"- Type: {c.category or 'other'}\n"
            f"- Source: `{src}`\n"
            f"- Status: {c.status}\n\n"
            f"## Analysis\n{c.evidence or '(see code)'}\n")


def _write_findings(ws: Path, findings: list[Candidate]) -> None:
    issues = ws / "issues"
    for c in findings:
        (issues / f"{_slug(c.endpoint or c.title)}.md").write_text(_issue_md(c), encoding="utf-8")
    (ws / "findings.json").write_text(json.dumps(
        {"findings": [{"title": c.title, "category": c.category, "entry": c.endpoint,
                       "file": c.file, "line": c.line, "severity": c.severity, "status": c.status}
                      for c in findings]}, indent=2, ensure_ascii=False), encoding="utf-8")


def _write_surface(ws: Path, units: list[Unit]) -> None:
    """Populate the attack-surface inventory from the unit worklist: in a coded run
    the enumerated surface IS the worklist, one row per unit, so the denominator is
    explicit and the gate's surface check is satisfied."""
    lines = ["# Attack Surface Inventory", "",
             "Enumerated by the coded engine from the unit worklist, one row per unit.", "",
             "| Package | Entrypoint file | Unit | Status |", "|---|---|---|---|"]
    for u in units:
        owned = u.files[0] if u.files else u.name
        pkg = Path(owned).parts[0] if Path(owned).parts else ""
        lines.append(f"| {pkg} | {owned} | {u.name} | reviewed |")
    (ws / "inventory" / "_surface.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_refuted(ws: Path, refuted: list[tuple[Candidate, str]]) -> None:
    """Record what the verifier dropped, so a refutation is auditable, not invisible."""
    lines = ["# Refuted candidates", "",
             "Surfaced by a review pass, then refuted by the adversarial verifier on a "
             "named controlling fact. Recorded so a wrong refutation is visible.", ""]
    for c, reason in refuted:
        lines.append(f"- **{c.title}** ({c.severity} {c.category}) `{c.endpoint or c.file}`: {reason}")
    (ws / "_refuted.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _mark_units_reviewed(ws: Path) -> None:
    for u in (ws / "units").glob("*.md"):
        text = u.read_text(encoding="utf-8")
        u.write_text(re.sub(r"(?im)^-\s*Status:\s*open\s*$", "- Status: reviewed", text), encoding="utf-8")


# --- resume support: a run interrupted by a usage limit picks up where it stopped ---

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


def _load_union(ws: Path) -> dict:
    p = ws / "_union.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}
    except (OSError, json.JSONDecodeError):
        return {}
    pool: dict = {}
    for d in data.get("findings", []):
        c = _cand_from_dict(d)
        pool[c.key()] = c
    return pool


def _load_verified(ws: Path) -> dict:
    p = ws / "_verified.json"
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save_verified(ws: Path, verified: dict) -> None:
    (ws / "_verified.json").write_text(json.dumps(verified, indent=2, ensure_ascii=False), encoding="utf-8")


def _reviewed_slugs(ws: Path) -> set:
    return {u.stem for u in (ws / "units").glob("*.md")
            if re.search(r"(?im)^-\s*Status:\s*reviewed\s*$", u.read_text(encoding="utf-8"))}


def _md_field(text: str, key: str) -> str:
    m = re.search(rf"(?im)^\s*-?\s*{key}\s*:\s*(.+?)\s*$", text)
    return m.group(1).strip().strip("`").strip() if m else ""


def _parse_issue(path: Path) -> Candidate | None:
    """Parse an agent-written issues/<name>.md into a Candidate for coded dedup and
    verification, so those steps do not depend on the agent's prose."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    title = next((ln[2:].strip() for ln in text.splitlines() if ln.startswith("# ")), path.stem)
    sev_raw = _md_field(text, "(?:risk|severity)").upper()
    severity = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if s in sev_raw), "MEDIUM")
    # the body cites a location as `path.ext:line` or `path.ext:line-range`, capture
    # both so the report carries a precise location and dedup can use the line
    fm = re.search(r"([\w./-]+\.(?:py|js|ts|go|java|rb|php))(?::(\d+))?", text)
    return Candidate(
        title=title or path.stem,
        category=_md_field(text, "type"),
        endpoint=_md_field(text, "source"),
        file=fm.group(1) if fm else "",
        line=int(fm.group(2)) if (fm and fm.group(2)) else None,
        severity=severity,
        evidence=path.name,
        status="confirmed",
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
) -> FinalizeResult:
    """The coded post-fan-out pipeline: dedup, verify, report over the agent's issues.

    These steps are mechanical, so they are code, not agent prose: it reads
    `issues/*.md`, dedups by location and class, adversarially verifies each survivor
    (resumable, skipping any already in `_verified.json`), drops the refuted into
    `_refuted.md`, and writes the ranked `findings.json`."""
    ws = Path(workspace) / Path(target).resolve().name
    root = str(Path(target).resolve())

    cands = [c for c in (_parse_issue(p) for p in sorted((ws / "issues").glob("*.md"))) if c]
    sev_votes: dict = {}
    for c in cands:                       # duplicate issue files for one finding are its severity votes
        sev_votes.setdefault(c.key(), []).append(c.severity)
    pool: dict = {}
    merge(pool, cands)
    deduped = [
        replace(c, severity=calibrated(median(sev_votes.get(c.key(), [c.severity])), c.category, c.title))
        for c in collapse_colocated(list(pool.values()))
    ]

    vr: VerifyResult | None = None
    if verify and deduped:
        if verifier is None:
            if provider is None:
                raise ValueError("finalize needs a provider, or an injected verifier")
            verifier = ModelVerifier(provider=provider, model=model)
        verified = _load_verified(ws)
        to_verify = [c for c in deduped if _keystr(c) not in verified]
        new_vr = verify_findings(to_verify, verifier, root, votes=votes, concurrency=concurrency)
        for c in new_vr.confirmed:
            verified[_keystr(c)] = {"real": True, "reason": ""}
        for c, reason in new_vr.refuted:
            verified[_keystr(c)] = {"real": False, "reason": reason}
        _save_verified(ws, verified)
        confirmed = [c for c in deduped if verified.get(_keystr(c), {"real": True})["real"]]
        refuted = [(c, verified[_keystr(c)]["reason"]) for c in deduped
                   if not verified.get(_keystr(c), {"real": True})["real"]]
        vr = VerifyResult(confirmed=confirmed, refuted=refuted, errors=new_vr.errors)
        _write_refuted(ws, refuted)
        deduped = confirmed

    _write_findings(ws, deduped)
    return FinalizeResult(workspace=ws, parsed=len(cands), deduped=len(deduped), verify=vr)


@dataclass(frozen=True, kw_only=True)
class RunResult:
    scaffold: ScaffoldResult
    accumulator: Accumulator
    units: int
    verify: VerifyResult | None = None   # None when verification was skipped


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
) -> RunResult:
    root = str(Path(target).resolve())
    res = scaffold(target, workspace, fresh=fresh)
    ws = res.workspace
    units = build_units(root, res.candidate_files, res.trace_targets)

    # resume: skip units a prior run already reviewed, carry its union forward
    reviewed = set() if fresh else _reviewed_slugs(ws)
    open_units = [u for u in units if _unit_slug(u.name) not in reviewed]
    acc = Accumulator(converge_after=converge_after, pool=({} if fresh else _load_union(ws)))

    shared = (ws / "_stack.md").read_text(encoding="utf-8")
    if reviewer is None:
        if provider is None:
            raise ValueError("run_repo_review needs a provider, or an injected reviewer")
        reviewer = ModelReviewer(provider=provider, model=model)

    run_passes(
        open_units, reviewer,
        converge_after=converge_after, max_passes=max_passes,
        shared_context=shared, concurrency=concurrency, on_pass=on_pass,
        persist=lambda f: _save_union(ws, f), accumulator=acc,
    )
    _save_union(ws, acc.findings)
    _mark_units_reviewed(ws)

    # adversarial verification: refute the union's candidates, keep survivors. Resumable,
    # a finding already in _verified.json is not re-verified.
    findings = acc.findings
    vr: VerifyResult | None = None
    if verify:
        if verifier is None:
            if provider is None:
                raise ValueError("verification needs a provider, or an injected verifier")
            verifier = ModelVerifier(provider=provider, model=model)
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
        vr = VerifyResult(confirmed=confirmed, refuted=refuted, errors=new_vr.errors)
        _write_refuted(ws, refuted)
        findings = confirmed

    _write_surface(ws, units)
    _write_findings(ws, findings)
    return RunResult(scaffold=res, accumulator=acc, units=len(units), verify=vr)
