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
) -> tuple[list[Finding], list[tuple[Finding, str]]]:
    """Audit a diff and return (kept findings, dropped (finding, reason)).

    A diff over the size budget is audited one file at a time so it does not
    overflow the context. Finding categories are normalized to the rule-id set."""
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
        return FindingsFilter().filter(findings)
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="codejury")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("dry-run", help="run the diff engine with a mock provider, no key")

    a = sub.add_parser("audit", help="audit a unified diff for security findings")
    a.add_argument("--diff-file", default=None, help="unified diff file (default: read stdin)")
    a.add_argument("--repo", default=None, help="repo path for --git-range")
    a.add_argument("--git-range", default=None, help="git range to diff, e.g. origin/main...HEAD")
    a.add_argument("--mode", choices=("standard", "adversarial"), default="standard")
    a.add_argument("--rounds", type=int, default=3, help="adversarial debate rounds")
    a.add_argument("--provider", choices=PROVIDERS, default="anthropic")
    a.add_argument("--model", default=DEFAULT_MODEL)
    a.add_argument("--finder-model", default=DEFAULT_FINDER_MODEL, help="adversarial: finder role model (default: --model)")
    a.add_argument("--challenger-model", default=DEFAULT_CHALLENGER_MODEL, help="adversarial: challenger role model")
    a.add_argument("--judge-model", default=DEFAULT_JUDGE_MODEL, help="adversarial: judge role model")
    a.add_argument("--api-base", default=DEFAULT_API_BASE)
    a.add_argument("--api-key", default=DEFAULT_API_KEY)
    a.add_argument("--retries", type=int, default=2, help="provider retry attempts on transient failure")
    a.add_argument("--format", choices=_FORMATS, default="text", dest="fmt")
    a.add_argument("--no-filter", action="store_true", help="skip the false-positive filter")
    a.add_argument("--fail-on", choices=_FAIL_ON, default=None, dest="fail_on")

    fr = sub.add_parser("full-review", help="scaffold a whole-repo review for an interactive agent")
    fr.add_argument("directory", help="target repository to review")
    fr.add_argument("--workspace", default="codejury-review", help="where to create the review workspace")

    args = parser.parse_args(argv)
    try:
        return _dispatch(args, parser)
    except Exception as exc:
        print(f"{args.command or 'codejury'} failed: {exc}", file=sys.stderr)
        return 1


def _dispatch(args, parser) -> int:
    if args.command == "audit":
        provider = make_provider(args.provider, api_key=args.api_key, api_base=args.api_base, retries=args.retries)
        kept, _ = audit_diff(
            _read_diff(args), provider=provider, model=args.model,
            mode=args.mode, max_rounds=args.rounds, filter_findings=not args.no_filter,
            finder_model=args.finder_model, challenger_model=args.challenger_model, judge_model=args.judge_model,
        )
        print(render(args.fmt, kept))
        return 1 if gate(kept, args.fail_on) else 0

    if args.command == "full-review":
        res = scaffold(args.directory, args.workspace)
        print(f"Workspace: {res.workspace}", file=sys.stderr)
        print(f"Seeded {res.entrypoints} entrypoints into {res.workspace}/api/_entrypoints.md", file=sys.stderr)
        print(f"Memory: {res.memory_path}", file=sys.stderr)
        print("\nRun this review with an interactive agent (Claude Code / Codex) using the methodology below.\n")
        print(res.methodology)
        return 0

    if args.command in (None, "dry-run"):
        kept, _ = audit_diff(
            _dry_run_diff(),
            provider=MockProvider(default='{"findings": [{"file": "app.py", "line": 1, "severity": "HIGH", '
                                          '"category": "sql_injection", "description": "[mock] no backend called", '
                                          '"confidence": 0.9}]}'),
            model="mock",
        )
        print(render("text", kept))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
