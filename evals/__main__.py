"""Eval CLI: score a review, run the diff probe, or compare two results.

  python -m evals repo openwebui --findings-dir /tmp/cj-owui/webui/findings
  python -m evals repo openwebui --findings-json findings.json --json before.json
  python -m evals diff --mode standard --model <id>
  python -m evals compare before.json after.json
  python -m evals coverage

The repo path scores the output an agent or a coded run already wrote, it does not run the
review. Resolve a benchmark by name across the public benchmarks and any private source in
the local config, see registry.py.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from evals import registry
from evals.compare import compare_files, format_compare
from evals.results import Result
from evals.runners.repo import reports_from_findings_dir, reports_from_json, score_repo
from evals.schema import load_answer_key


def _format_result(res: Result) -> str:
    lines = [f"=== {res.target} ===",
             f"  recall    {len(res.found)}/{res.n_planted} = {res.recall:.0%}",
             f"  precision {res.precision_known:.0%}  (over {len(res.found) + len(res.false_positives)} known-matched of {res.n_reports} reports)"]
    if res.missed:
        lines.append(f"  MISSED: {', '.join(res.missed)}")
    if res.false_positives:
        lines.append(f"  false positive on safe: {', '.join(res.false_positives)}")
    if res.extra:
        lines.append(f"  extra (unkeyed, read by hand): {len(res.extra)}")
    if res.errors:
        lines.append(f"  errors: {res.errors}")
    return "\n".join(lines)


def _emit(res: Result, json_out: str | None) -> int:
    print(_format_result(res))
    if json_out:
        Path(json_out).write_text(json.dumps(res.to_dict(), indent=2), encoding="utf-8")
    clean = not res.missed and not res.false_positives and not res.errors
    return 0 if clean else 1


def _cmd_repo(args) -> int:
    key = load_answer_key(registry.find_answer_key(args.name))
    if args.findings_json:
        reports = reports_from_json(args.findings_json)
    elif args.findings_dir:
        reports = reports_from_findings_dir(args.findings_dir)
    else:
        reports = reports_from_findings_dir(Path(args.workspace) / args.name / "findings")
    return _emit(score_repo(key, reports), args.json)


def _cmd_diff(args) -> int:
    from codejury.providers.factory import DEFAULT_API_BASE, DEFAULT_API_KEY, DEFAULT_MODEL, make_provider
    from evals.runners.diff import default_cases, load_cases, run_diff_cases

    cases = load_cases(args.cases) if args.cases else default_cases()
    provider = make_provider("litellm", api_key=DEFAULT_API_KEY, api_base=DEFAULT_API_BASE, retries=2)
    res = run_diff_cases(cases, provider=provider, model=args.model or DEFAULT_MODEL, mode=args.mode)
    return _emit(res, args.json)


def _cmd_compare(args) -> int:
    print(format_compare(compare_files(args.before, args.after)))
    return 0


def _cmd_coverage(args) -> int:
    from evals.knowledge import coverage_matrix, coverage_problems, format_matrix

    cov = coverage_matrix()
    problems = coverage_problems(cov)
    print(format_matrix(cov, problems))
    # a missing case is a known gap the case library fills over time, but a reference to a
    # knowledge file that does not exist is broken benchmark data, so fail loud on it
    unresolved = [p for p in problems if p.kind == "unresolved-reference"]
    return 1 if unresolved else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="evals", description="detection-quality eval ruler")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("repo", help="score a whole-repo review against an answer key")
    r.add_argument("name", help="benchmark name, e.g. openwebui")
    r.add_argument("--workspace", default=None, help="review workspace root, reads <workspace>/<name>/findings")
    r.add_argument("--findings-dir", default=None, help="a findings/ directory directly")
    r.add_argument("--findings-json", default=None, help="a findings.json or a json list of reports")
    r.add_argument("--json", default=None, help="write the structured result here for compare")
    r.set_defaults(func=_cmd_repo)

    d = sub.add_parser("diff", help="run the diff capability probe and score")
    d.add_argument("--mode", default="standard")
    d.add_argument("--model", default=None)
    d.add_argument("--cases", default=None, help="cases yaml, defaults to the shipped diff cases")
    d.add_argument("--json", default=None)
    d.set_defaults(func=_cmd_diff)

    c = sub.add_parser("compare", help="compare two result json files")
    c.add_argument("before")
    c.add_argument("after")
    c.set_defaults(func=_cmd_compare)

    cov = sub.add_parser("coverage", help="knowledge coverage matrix, which files lack eval coverage")
    cov.set_defaults(func=_cmd_coverage)

    args = p.parse_args(argv)
    if args.cmd == "repo" and not (args.findings_dir or args.findings_json or args.workspace):
        p.error("repo needs one of --workspace, --findings-dir, or --findings-json")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
