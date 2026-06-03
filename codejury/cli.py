"""Command line interface: thin argument parsing and dispatch.

Two paths matched to their nature:

- ``diff`` runs the coded diff engine over a unified diff: a single balanced call
  (standard) or the adversarial Finder/Challenger/Judge pass.
- ``review <dir>`` scaffolds a workspace and prints the methodology for an
  interactive agent to run a whole-repo review (it does not run an LLM pipeline,
  which a single call cannot do for a whole codebase).

``diff --dry-run`` exercises the engine with a mock provider and no key.
The audit orchestration itself lives in ``codejury.diff.runner``.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

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
from codejury.review.scaffold import scaffold

_FORMATS = ("text", "markdown", "json", "sarif")
_FAIL_ON = ("critical", "high", "medium", "low")


def _read_diff(args) -> str:
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            return f.read()
    if args.git_range:
        return subprocess.run(
            ["git", "-C", args.repo or ".", "diff", args.git_range],
            capture_output=True, text=True, check=True,
        ).stdout
    return sys.stdin.read()


def _dry_run_diff() -> str:
    return "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


# canned reply for `diff --dry-run`: a mock provider returns this so the
# pipeline runs end to end with no key and no backend call
_MOCK_REPLY = (
    '{"findings": [{"file": "app.py", "line": 1, "severity": "HIGH", '
    '"category": "sql_injection", "description": "[mock] no backend called", '
    '"confidence": 0.9}]}'
)


def _add_audit_args(p) -> None:
    """The diff-audit flags for `diff`."""
    p.add_argument("--file", default=None, help="unified diff file (default: read stdin)")
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

    _add_audit_args(sub.add_parser("diff", help="audit a unified diff (the coded engine)"))

    review = sub.add_parser("review", help="scaffold a whole-repo review for an interactive agent")
    review.add_argument("directory", help="target repository to review")
    review.add_argument("--workspace", default="codejury-review", help="where to create the review workspace")

    inst = sub.add_parser("install-slash-command",
                          help="install the /codejury-review slash command for an agent")
    inst.add_argument("--agent", choices=("claude", "codex"), default="claude",
                      help="which agent's command directory to install into")
    inst.add_argument("--dir", default=None, help="explicit target directory, overrides --agent")

    args = parser.parse_args(argv)
    try:
        return _dispatch(args, parser)
    except Exception as exc:
        label = getattr(args, "command", None) or "codejury"
        print(f"{label} failed: {exc}", file=sys.stderr)
        return 1


def _dispatch(args, parser) -> int:
    if args.command == "diff":
        if args.dry_run:
            provider = MockProvider(default=_MOCK_REPLY)
            model = "mock"
            # zero-config smoke test: fall back to a built-in demo diff when none is supplied
            diff = _read_diff(args) if (args.file or args.git_range) else _dry_run_diff()
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

    if args.command == "review":
        res = scaffold(args.directory, args.workspace)
        (Path(res.workspace) / "METHODOLOGY.md").write_text(res.methodology, encoding="utf-8")
        print(f"Workspace ready: {res.workspace}", file=sys.stderr)
        if res.guides:
            print(f"Detected stack: {', '.join(res.guides)}, notes in {res.workspace}/_stack.md", file=sys.stderr)
        print(f"Flagged {len(res.candidate_files)} candidate entrypoint files into "
              f"{res.workspace}/entrypoints/_entrypoints.md", file=sys.stderr)
        print(f"Methodology: {res.workspace}/METHODOLOGY.md", file=sys.stderr)
        print(
            "This command sets up the review, it does not find the issues itself. Next, have an "
            f"interactive agent follow {res.workspace}/METHODOLOGY.md to run the review, or use the "
            "/codejury-review command in Claude Code or Codex. Findings are written to "
            f"{res.workspace}/issues/."
        )
        return 0

    if args.command == "install-slash-command":
        from codejury.resources import COMMANDS_DIR
        # the command body is portable, only the directory differs per agent
        agent_dirs = {
            "claude": Path.home() / ".claude" / "commands",
            "codex": Path.home() / ".codex" / "prompts",
        }
        target_dir = Path(args.dir) if args.dir else agent_dirs[args.agent]
        target_dir.mkdir(parents=True, exist_ok=True)
        name = "codejury-review.md"
        dst = target_dir / name
        dst.write_text((COMMANDS_DIR / name).read_text(encoding="utf-8"), encoding="utf-8")
        print(f"Installed slash command to {dst}")
        print("Run it in the agent with: /codejury-review <repository>")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
