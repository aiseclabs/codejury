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
    return file_hit and category_match(report.category, entry.category)


def score(key: AnswerKey, reports: list[Report]) -> Result:
    res = Result(target=key.target, n_planted=len(key.planted), n_reports=len(reports))
    matched_reports: set[str] = set()
    for p in key.planted:
        hit = next((r for r in reports if _matches(r, p)), None)
        if hit is not None:
            res.found.append(p.id)
            matched_reports.add(hit.name)
        else:
            res.missed.append(p.id)
    for s in key.safe:
        for r in reports:
            if _matches(r, s):
                res.false_positives.append(r.name)
                matched_reports.add(r.name)
    res.extra = [r.name for r in reports if r.name not in matched_reports]
    return res
