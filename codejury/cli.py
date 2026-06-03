"""codejury CLI: thin argument parsing and dispatch.

Two paths matched to their nature:

- ``review diff`` runs the coded diff engine over a unified diff: a single
  balanced call (standard) or the adversarial Finder/Challenger/Judge pass.
- ``review repo`` scaffolds a workspace and prints the methodology for an
  interactive agent to run a whole-repo review (it does not run an LLM pipeline,
  which a single call cannot do for a whole codebase).

``review diff --dry-run`` exercises the engine with a mock provider and no key.
The audit orchestration itself lives in ``codejury.diff.runner``.
"""

from __future__ import annotations

import argparse
import subprocess
import sys

from codejury import __version__
from codejury.report import gate, render
from codejury.diff.runner import audit_diff
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
from codejury.repo.scaffold import scaffold

_FORMATS = ("text", "markdown", "json", "sarif")
_FAIL_ON = ("critical", "high", "medium", "low")


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
        print(f"Seeded {res.entrypoints} entrypoints into {res.workspace}/entrypoints/_entrypoints.md", file=sys.stderr)
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
