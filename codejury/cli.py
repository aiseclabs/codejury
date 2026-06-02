"""codejury CLI.

Two entry points matched to their nature:

- ``audit`` runs the coded diff engine over a unified diff: a single balanced
  call (standard) or the adversarial Finder/Challenger/Judge pass.
- ``full-review`` scaffolds a workspace and prints the methodology for an
  interactive agent to run a whole-repo review (it does not run an LLM pipeline,
  which a single call cannot do for a whole codebase).

``dry-run`` exercises the diff engine with a mock provider and no API key.
"""

from __future__ import annotations

import argparse
import subprocess
import sys

import dataclasses

from codejury import __version__
from codejury.diff.debate import AdversarialAuditRunner
from codejury.diff.engine import AuditRunner
from codejury.diff.findings_filter import FindingsFilter
from codejury.diff.report import gate, render
from codejury.diff.rules import allowed_categories, normalize_category
from codejury.domain.finding import Finding

# A diff larger than this is audited file-by-file so a big PR does not overflow
# the model's context and silently truncate the reply.
_MAX_DIFF_CHARS = 60_000
from codejury.fullreview.scaffold import scaffold
from codejury.providers.factory import (
    DEFAULT_API_BASE,
    DEFAULT_API_KEY,
    DEFAULT_CHALLENGER_MODEL,
    DEFAULT_FINDER_MODEL,
    DEFAULT_JUDGE_MODEL,
    DEFAULT_MODEL,
    PROVIDERS,
    make_provider,
)
from codejury.providers.mock import MockProvider

_FORMATS = ("text", "markdown", "json", "sarif")
_FAIL_ON = ("critical", "high", "medium", "low")


def _split_diff_by_file(diff: str) -> list[str]:
    """Split a unified diff into one diff per file (`diff --git ...` boundaries)."""
    chunks: list[str] = []
    cur: list[str] = []
    for line in diff.splitlines(keepends=True):
        if line.startswith("diff --git ") and cur:
            chunks.append("".join(cur))
            cur = []
        cur.append(line)
    if cur:
        chunks.append("".join(cur))
    return chunks or ([diff] if diff.strip() else [])


def _dedup_findings(findings: list[Finding]) -> list[Finding]:
    seen: set = set()
    out: list[Finding] = []
    for f in findings:
        k = (f.file, f.line, f.category, f.description)
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def audit_diff(
    diff: str,
    *,
    provider,
    model: str,
    mode: str = "standard",
    max_rounds: int = 3,
    filter_findings: bool = True,
    finder_model: str | None = None,
    challenger_model: str | None = None,
    judge_model: str | None = None,
    exclude_paths: tuple[str, ...] = (),
) -> tuple[list[Finding], list[tuple[Finding, str]]]:
    """Audit a diff and return (kept findings, dropped (finding, reason)).

    A diff over the size budget is audited one file at a time so it does not
    overflow the context. Finding categories are normalized to the rule-id set.
    ``exclude_paths`` are operator-supplied path substrings to drop."""
    def _run_one(d: str) -> list[Finding]:
        if mode == "adversarial":
            return AdversarialAuditRunner(
                provider=provider, model=model,
                finder_model=finder_model, challenger_model=challenger_model, judge_model=judge_model,
            ).run(d, max_rounds=max_rounds).findings
        return AuditRunner(provider=provider, model=model).run(d)

    if len(diff) > _MAX_DIFF_CHARS:
        chunks = _split_diff_by_file(diff)
        findings = _dedup_findings([f for c in chunks for f in _run_one(c)])
    else:
        findings = _run_one(diff)

    allowed = set(allowed_categories())
    findings = [dataclasses.replace(f, category=normalize_category(f.category, allowed)) for f in findings]
    if filter_findings:
        return FindingsFilter(exclude_paths=exclude_paths).filter(findings)
    return findings, []


def _read_diff(args) -> str:
    if args.diff_file:
        with open(args.diff_file, encoding="utf-8") as f:
            return f.read()
    if args.git_range:
        return subprocess.run(
            ["git", "-C", args.repo or ".", "diff", args.git_range],
            capture_output=True, text=True, check=True,
        ).stdout
    return sys.stdin.read()


def _dry_run_diff() -> str:
    return "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


# canned reply for `review diff --dry-run`: a mock provider returns this so the
# pipeline runs end to end with no key and no backend call
_MOCK_REPLY = (
    '{"findings": [{"file": "app.py", "line": 1, "severity": "HIGH", '
    '"category": "sql_injection", "description": "[mock] no backend called", '
    '"confidence": 0.9}]}'
)


def _add_audit_args(p) -> None:
    """The diff-audit flags for `review diff`."""
    p.add_argument("--diff-file", default=None, help="unified diff file (default: read stdin)")
    p.add_argument("--repo", default=None, help="repo path for --git-range")
    p.add_argument("--git-range", default=None, help="git range to diff, e.g. origin/main...HEAD")
    p.add_argument("--dry-run", action="store_true",
                   help="run the engine with a mock provider and no key (a built-in demo diff if none is given)")
    p.add_argument("--exclude", action="append", default=None, metavar="PATH",
                   help="drop findings whose file path contains this substring (repeatable)")
    p.add_argument("--mode", choices=("standard", "adversarial"), default="standard")
    p.add_argument("--rounds", type=int, default=3, help="adversarial only: debate rounds")
    p.add_argument("--provider", choices=PROVIDERS, default="anthropic")
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--finder-model", default=DEFAULT_FINDER_MODEL, help="adversarial only: finder role model (default: --model)")
    p.add_argument("--challenger-model", default=DEFAULT_CHALLENGER_MODEL, help="adversarial only: challenger role model")
    p.add_argument("--judge-model", default=DEFAULT_JUDGE_MODEL, help="adversarial only: judge role model")
    p.add_argument("--api-base", default=DEFAULT_API_BASE)
    p.add_argument("--api-key", default=DEFAULT_API_KEY)
    p.add_argument("--retries", type=int, default=2, help="provider retry attempts on transient failure")
    p.add_argument("--format", choices=_FORMATS, default="text", dest="fmt")
    p.add_argument("--no-filter", action="store_true", help="skip the false-positive filter")
    p.add_argument("--fail-on", choices=_FAIL_ON, default=None, dest="fail_on")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="codejury")
    parser.add_argument("--version", action="version", version=f"codejury {__version__}")
    sub = parser.add_subparsers(dest="command")

    review = sub.add_parser("review", help="review code for security findings")
    rsub = review.add_subparsers(dest="scope")
    _add_audit_args(rsub.add_parser("diff", help="audit a unified diff (the coded engine)"))
    repo = rsub.add_parser("repo", help="scaffold a whole-repo review for an interactive agent")
    repo.add_argument("directory", help="target repository to review")
    repo.add_argument("--workspace", default="codejury-review", help="where to create the review workspace")

    args = parser.parse_args(argv)
    try:
        return _dispatch(args, parser)
    except Exception as exc:
        label = getattr(args, "command", None) or "codejury"
        print(f"{label} failed: {exc}", file=sys.stderr)
        return 1


def _dispatch(args, parser) -> int:
    scope = getattr(args, "scope", None)
    if args.command == "review" and scope == "diff":
        if args.dry_run:
            provider = MockProvider(default=_MOCK_REPLY)
            model = "mock"
            # zero-config smoke test: fall back to a built-in demo diff when none is supplied
            diff = _read_diff(args) if (args.diff_file or args.git_range) else _dry_run_diff()
        else:
            provider = make_provider(args.provider, api_key=args.api_key, api_base=args.api_base, retries=args.retries)
            model = args.model
            diff = _read_diff(args)
        kept, _ = audit_diff(
            diff, provider=provider, model=model,
            mode=args.mode, max_rounds=args.rounds, filter_findings=not args.no_filter,
            finder_model=args.finder_model, challenger_model=args.challenger_model, judge_model=args.judge_model,
            exclude_paths=tuple(args.exclude or ()),
        )
        print(render(args.fmt, kept))
        return 1 if gate(kept, args.fail_on) else 0

    if args.command == "review" and scope == "repo":
        res = scaffold(args.directory, args.workspace)
        print(f"Workspace: {res.workspace}", file=sys.stderr)
        print(f"Seeded {res.entrypoints} entrypoints into {res.workspace}/api/_entrypoints.md", file=sys.stderr)
        print(f"Memory: {res.memory_path}", file=sys.stderr)
        print("\nRun this review with an interactive agent (Claude Code / Codex) using the methodology below.\n")
        print(res.methodology)
        return 0

    if args.command == "review":  # no scope given
        print("usage: codejury review {diff,repo} ...", file=sys.stderr)
        print("  diff   audit a unified diff for security findings", file=sys.stderr)
        print("  repo   scaffold a whole-repo review for an interactive agent", file=sys.stderr)
        return 1

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
