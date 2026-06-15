"""Cross-pass accumulation and convergence for the multi-pass union engine.

A single review pass over a large repo is shallow and its misses land somewhere
different each time, so one pass is random and incomplete. Recall is a multi-pass
property: run many independent passes, each covering every unit with a different
lens, and take the union. This module is the deterministic core of that, the part
that makes the result converge and stop being random:

- `merge` folds a pass's candidates into the running union, deduped by location, so
  a finding several passes reach is counted once and the union only grows.
- `Accumulator` tracks the union and the per-pass new-finding counts, and reports
  convergence: the union is complete enough to stop when the last K passes each add
  nothing new. The orchestration keeps spawning passes until then.

This holds no model logic and makes no calls, so it is fully testable on its own.
The per-pass review that produces candidates is injected, see the engine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace

from codejury.review.repo.severity import calibrated, median


@dataclass(frozen=True, kw_only=True)
class Candidate:
    """One finding a pass proposed, before cross-pass dedup and verification."""
    title: str
    category: str = ""
    endpoint: str = ""
    file: str = ""
    line: int | None = None
    severity: str = "HIGH"
    evidence: str = ""
    status: str = "confirmed"
    source: str = ""   # agent candidate file basename, links a finding to its candidate and poc, empty in the coded run

    def key(self, by_file: bool = False) -> tuple:
        """The dedup identity, location plus class. Endpoint is the precise location
        when a pass records it, path params normalized so /x/<id> and /x/{id}
        collapse. Otherwise fall back to file. The category is always part of the key,
        so two distinct classes on the same endpoint, a missing binding and a race on
        the same token route, stay separate findings and are not merged away.

        With `by_file`, the endpoint is dropped from the key and findings collapse by file
        and class. A domain whose endpoint is a function sets this, since one root cause in
        a shared helper is reported at every caller and is one finding, not one per function."""
        cat = self.category.strip().lower()
        if self.endpoint and not by_file:
            ep = re.sub(r"\s+", " ", re.sub(r"[<{][^>}]*[>}]", "*", self.endpoint.strip().lower()))
            return ("ep", ep, cat)
        return ("fc", self.file.strip().lower(), cat)


def merge(pool: dict[tuple, Candidate], incoming: list[Candidate], by_file: bool = False) -> int:
    """Fold `incoming` into `pool` keyed by location, return how many were new.

    A duplicate does not overwrite, except a confirmed candidate upgrades a blocked
    one at the same location, since a later pass that confirms what an earlier pass
    could only block is strictly more informative."""
    new = 0
    for cand in incoming:
        k = cand.key(by_file)
        existing = pool.get(k)
        if existing is None:
            pool[k] = cand
            new += 1
        elif existing.status != "confirmed" and cand.status == "confirmed":
            pool[k] = cand
    return new


def collapse_colocated(cands: list[Candidate]) -> list[Candidate]:
    """Merge candidates that cite the exact same file, line, and class, preserving order.

    The primary `key()` dedups by endpoint, but two passes can label one defect with
    different endpoint prose, a controller method on one pass and the HTTP route on
    another, so they survive endpoint dedup. An identical file, line, and category is
    the same defect by its objective location, so collapse those too. Only applies when
    a line is present, so a finding with no parsed line is never merged on file alone,
    which keeps recall safe."""
    seen: set[tuple] = set()
    out: list[Candidate] = []
    for c in cands:
        if c.file and c.line is not None:
            lk = (c.file.strip().lower(), c.line, c.category.strip().lower())
            if lk in seen:
                continue
            seen.add(lk)
        out.append(c)
    return out


@dataclass
class Accumulator:
    """The running union plus the convergence signal across passes."""
    converge_after: int = 2
    pool: dict[tuple, Candidate] = field(default_factory=dict)
    new_per_pass: list[int] = field(default_factory=list)
    errors: int = 0   # unit reviews that raised, counted not dropped, invariant 3
    failed_units: set[str] = field(default_factory=set)   # never reviewed cleanly, left open so the gate catches them
    sev_votes: dict[tuple, list[str]] = field(default_factory=dict)
    severity_floors: tuple[tuple[str, str], ...] | None = None   # the domain's floor table, web default when None
    dedup_by_file: bool = False   # the domain's dedup granularity, endpoint-aware when False

    def add_pass(self, candidates: list[Candidate]) -> int:
        for c in candidates:
            self.sev_votes.setdefault(c.key(self.dedup_by_file), []).append(c.severity)
        n = merge(self.pool, candidates, self.dedup_by_file)
        self.new_per_pass.append(n)
        return n

    @property
    def converged(self) -> bool:
        """True once the last `converge_after` passes each added nothing new. Needs at
        least that many passes, so a single empty pass never converges on its own."""
        if len(self.new_per_pass) < self.converge_after:
            return False
        return all(n == 0 for n in self.new_per_pass[-self.converge_after:])

    @property
    def findings(self) -> list[Candidate]:
        """The union, each finding's severity calibrated: the median of the grades it
        was given across passes, raised to the firm-rule floor for its class."""
        out: list[Candidate] = []
        for k, c in self.pool.items():
            sev = calibrated(median(self.sev_votes.get(k, [c.severity])), c.category, c.title, self.severity_floors)
            out.append(replace(c, severity=sev) if sev != c.severity else c)
        return out
