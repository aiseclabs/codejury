"""Repo-path eval runner: score a whole-repo review's output against an answer key.

The whole-repo review is agent driven, so this does not run it, it reads the findings the
review wrote and scores them. Reports come from the confirmed `findings/*.md` a finalize
produced, or a `findings.json`, or any json list of reports, so one answer key scores a
coded run and an agent run alike.
"""

from __future__ import annotations

from evals.results import Result
from evals.schema import AnswerKey, Report
from evals.scorers.parse import reports_from_findings_dir, reports_from_json
from evals.scorers.score import score

__all__ = ["reports_from_findings_dir", "reports_from_json", "score_repo"]


def score_repo(key: AnswerKey, reports: list[Report]) -> Result:
    return score(key, reports)
