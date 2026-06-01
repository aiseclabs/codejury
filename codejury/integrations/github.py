"""Post audit results to a GitHub pull request as a review with inline comments.

``build_review`` is a pure function (results -> GitHub review payload) so it is
unit-testable; ``post_review`` does the HTTP POST and accepts an injectable
transport so it can be tested without a token or a live PR. Problems with a
usable file:line become inline comments; everything else is summarized in the
review body. The review requests changes when any problem is found.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any, Callable

from codejury.domain.observation import Observation
from codejury.domain.result import AnalysisResult

Results = list[tuple[str, AnalysisResult]]


def build_review(results: Results, *, max_comments: int = 50) -> dict:
    comments: list[dict] = []
    problems = 0
    for _path, result in results:
        for o in result.observations:
            comment = _inline_comment(o)
            if comment is None:
                continue
            problems += 1
            if len(comments) < max_comments:
                comments.append(comment)

    body = (
        f"codejury found {problems} issue(s)." if problems else "codejury found no issues."
    )
    if problems > len(comments):
        body += f" Showing {len(comments)} inline; {problems - len(comments)} more omitted."
    return {
        "body": body,
        "event": "REQUEST_CHANGES" if problems else "COMMENT",
        "comments": comments,
    }


def _inline_comment(o: Observation) -> dict | None:
    if o.kind == "finding":
        evidence = o.evidence[0] if o.evidence else None
        if evidence and evidence.file and evidence.line:
            cwe = f" ({o.cwe})" if o.cwe else ""
            return {"path": evidence.file, "line": evidence.line, "body": f"**{o.severity}{cwe}** {o.title}\n\n{o.description}"}
    if o.kind == "verdict" and o.status == "VULNERABLE":
        evidence = o.evidence[0] if o.evidence else None
        if evidence and evidence.file and evidence.line:
            return {"path": evidence.file, "line": evidence.line, "body": f"**VULNERABLE** `{o.capability}`\n\n{o.reasoning}"}
    return None


def post_review(
    owner: str,
    repo: str,
    pull: int,
    payload: dict,
    *,
    token: str,
    transport: Callable[[str, bytes, dict], Any] | None = None,
) -> Any:
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pull}/reviews"
    data = json.dumps(payload).encode()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
    }
    if transport is not None:
        return transport(url, data, headers)
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(request) as response:
        return response.status


def parse_pr_ref(ref: str) -> tuple[str, str, int]:
    """Parse 'owner/repo#123' into (owner, repo, pull_number)."""
    repo_part, _, number = ref.partition("#")
    owner, _, repo = repo_part.partition("/")
    if not owner or not repo or not number.isdigit():
        raise ValueError(f"expected owner/repo#number, got {ref!r}")
    return owner, repo, int(number)
