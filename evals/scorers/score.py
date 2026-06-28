"""The score algorithm: match every report against an answer key and tally the result.

This is the shared end of both paths. A planted issue is found when some report matches it,
a report on a safe lookalike is a false positive, a report on neither is extra and kept for
a human since it may be a real bug the key misses.
"""

from __future__ import annotations

from pathlib import Path

from evals.results import Result
from evals.schema import AnswerKey, KeyEntry, Report
from evals.scorers.match import category_match, endpoint_match


def _matches(report: Report, entry: KeyEntry) -> bool:
    # endpoint is the precise signal: when the key entry cites one, the report must match
    # it exactly, no loose file fallback that would credit a report on a sibling endpoint
    if entry.entry:
        return bool(report.endpoint) and endpoint_match(report.endpoint, entry.entry)
    # no endpoint on the key entry, fall back to a matching category at any accepted file
    # anchor, so a report at the sink or at a call site that feeds it both count, for a
    # class such as code injection an endpoint does not anchor
    report_names = {Path(f).name for f in report.files}
    file_hit = any(Path(kf).name in report_names for kf in entry.files)
    if not file_hit:
        return False
    # symbols narrow a file anchor to the bug's real framing, so a report of the same class on
    # a sibling function in the same file no longer credits it.
    if entry.symbols:
        hay = f"{report.text} {report.endpoint}"
        # the file plus the bug's own function is a precise anchor, so the class label is then
        # redundant: a report that traces the same function at the same file is the same defect
        # even when it names the class idor where the key names it access-control. A symbol miss
        # still rejects, since that is a different function in the file, not this bug.
        return any(s in hay for s in entry.symbols)
    # no symbols, so the class is the only thing that narrows a whole-file anchor to the bug
    return category_match(report.category, entry.category)


def score(key: AnswerKey, reports: list[Report]) -> Result:
    res = Result(target=key.target, n_planted=len(key.planted), n_reports=len(reports))
    matched_reports: set[str] = set()
    for p in key.planted:
        # credit a report to one planted entry only, so a single report cannot satisfy two
        # planted entries that share a loose file and class anchor and inflate recall
        hit = next((r for r in reports if r.name not in matched_reports and _matches(r, p)), None)
        if hit is not None:
            res.found.append(p.id)
            matched_reports.add(hit.name)
        else:
            res.missed.append(p.id)
    for s in key.safe:
        for r in reports:
            # count a report once: skip one already credited to a planted finding or to an
            # earlier safe anchor, so a report matching several safe entries is one false
            # positive, not several, which would understate precision
            if r.name in matched_reports:
                continue
            if _matches(r, s):
                res.false_positives.append(r.name)
                matched_reports.add(r.name)
    res.extra = [r.name for r in reports if r.name not in matched_reports]
    return res
