"""The pass-loop: the deterministic multi-pass orchestration of a repo review.

This is the part that is mechanical, not a matter of the agent's judgment, so it is
code, not prose. It runs the whole unit worklist every pass, cycles a different lens
each pass so the passes' blind spots land in different places, folds every pass into
the running union, and stops only when the union has converged. The per-unit
judgment is delegated to an injected `UnitReviewer`. Everything here, coverage,
diversity, accumulation, and the stop condition, is fixed by code so the result is
comprehensive and does not vary run to run.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from codejury.review.repo.reviewer import Unit, UnitReviewer
from codejury.review.repo.union import Accumulator

DEFAULT_LENSES = (
    "authorization",
    "replay",
    "concurrency",
    "data-exposure",
    "injection",
    "business-logic",
    "",
)


def run_passes(
    units: list[Unit],
    reviewer: UnitReviewer,
    *,
    lenses: tuple[str, ...] = DEFAULT_LENSES,
    converge_after: int = 2,
    max_passes: int = 24,
    shared_context: str = "",
    concurrency: int = 6,
    on_pass: Callable[[int, str, int, int], None] | None = None,
    persist: Callable[[list], None] | None = None,
    accumulator: Accumulator | None = None,
) -> Accumulator:
    """Run diverse passes over the worklist until the union converges or `max_passes`.

    Every pass reviews every unit, so coverage is total each pass. The lens rotates so
    diversity drives the union. Passes run in order, but the units within a pass are
    independent, so they run concurrently up to `concurrency`, since each is a network
    bound model call. Results are merged in unit order, so the converged finding set is
    the same as a serial run. `on_pass(pass_number, lens, new_this_pass, union_size)`
    is called after each pass for progress."""
    acc = accumulator if accumulator is not None else Accumulator(converge_after=converge_after)
    lenses = lenses or ("",)
    reviewed_ok: set[str] = set()

    def review_unit(unit: Unit, lens: str):
        try:
            return reviewer.review(unit, lens, shared_context=shared_context), None
        except Exception as exc:
            return [], exc

    for i in range(max_passes):
        lens = lenses[i % len(lenses)]
        if concurrency > 1 and len(units) > 1:
            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                per_unit = list(pool.map(lambda u: review_unit(u, lens), units))   # order preserved, the zip below relies on it
        else:
            per_unit = [review_unit(u, lens) for u in units]
        candidates = [c for cands, _err in per_unit for c in cands]
        acc.errors += sum(1 for _cands, err in per_unit if err is not None)
        reviewed_ok.update(u.name for u, (_cands, err) in zip(units, per_unit) if err is None)
        n_new = acc.add_pass(candidates)
        if persist is not None:
            persist(acc.findings)   # checkpoint the union each pass, so a kill mid-run can resume
        if on_pass is not None:
            on_pass(i + 1, lens, n_new, len(acc.findings))
        if acc.converged:
            break
    acc.failed_units = {u.name for u in units} - reviewed_ok
    return acc
