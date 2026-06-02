"""Command-line entry point.

``dry-run`` wires every mock layer together with no API key, proving the
contracts compose. ``audit`` runs the real pipeline against the capability
library, backed by the Anthropic provider, under a chosen orchestration strategy
(single verifier, or finder/challenger/judge debate).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from codejury.agents.mock import MockAgent
from codejury.assembly import (
    DEFAULT_API_BASE,
    DEFAULT_API_KEY,
    DEFAULT_MODEL,
    PROVIDERS,
    STRATEGIES,
    build_orchestration,
    build_skill_orchestration,
    make_provider,
    orchestration_descriptor,
    run_over_artifacts,
    run_over_artifacts_with_skills,
    run_over_source,
)
from codejury.domain.artifact import CodeArtifact
from codejury.domain.capability import Capability, load_capabilities
from codejury.domain.context import AnalysisContext
from codejury.domain.skill import Skill, load_skills
from codejury.selection import Selector, SkillRouter
from codejury.domain.observation import Observation
from codejury.domain.result import AnalysisResult
from codejury.evaluation import EvalReport, evaluate, load_cases
from codejury.infrastructure.cache import VerdictCache
from codejury.orchestrators.single import SingleOrchestrator
from codejury.providers.base import Provider
from codejury.providers.mock import MockProvider
from codejury.baseline import filter_new
from codejury.reporting import from_json, to_json, to_markdown, to_sarif
from codejury.resources import CAPABILITIES_DIR, GOLDEN_DIR, SKILLS_DIR, SUPPRESSIONS_FILE, TASKS_DIR
from codejury.suppression import filter_results, load_suppressions
from codejury.integrations.github import build_review, parse_pr_ref, post_review
from codejury.sources.chunker import Chunker
from codejury.sources.diff import DiffSource
from codejury.sources.repo import RepoSource
from codejury.tasks.base import run_task
from codejury.tasks.registry import load_tasks

_FORMATS = ("text", "markdown", "json", "sarif")


def dry_run() -> AnalysisResult:
    provider = MockProvider(default="[mock] no real backend was called")
    agent = MockAgent(provider=provider, role="verifier")
    orchestrator = SingleOrchestrator()
    skills = [
        Skill(id="authn", name="Authentication"),
        Skill(id="crypto", name="Cryptography"),
    ]
    ctx = AnalysisContext(
        artifact=CodeArtifact(kind="diff", path="auth.py", content="+ hashlib.sha256(pwd)"),
        skills=skills,
    )
    return orchestrator.run({"verifier": agent}, ctx)


def audit(
    diff_text: str,
    skills: list[Skill],
    *,
    provider: Provider,
    model: str,
    max_tokens: int = 2048,
    strategy: str = "single",
    cache: VerdictCache | None = None,
    router: SkillRouter | None = None,
) -> list[tuple[str, AnalysisResult]]:
    """Audit each changed file in `diff_text` on its selected skills, (path, result) per file."""
    agents, orchestrator = build_skill_orchestration(strategy, provider=provider, model=model, max_tokens=max_tokens)
    return run_over_artifacts_with_skills(
        DiffSource(diff_text).list_artifacts(), Selector(tuple(skills)), agents, orchestrator,
        router=router, cache=cache, orchestration=orchestration_descriptor(provider, strategy, model, max_tokens),
    )


def scan(
    directory: str,
    skills: list[Skill],
    *,
    provider: Provider,
    model: str,
    max_tokens: int = 2048,
    strategy: str = "pipeline",
    extensions: tuple[str, ...] = (".py",),
    max_chars: int = 200_000,
    with_callers: bool = False,
    with_callees: bool = False,
    cache: VerdictCache | None = None,
    router: SkillRouter | None = None,
) -> list[tuple[str, AnalysisResult]]:
    """Audit every matching file in a directory tree on its selected skills, (path, result) per artifact."""
    source = RepoSource(
        directory,
        extensions=extensions,
        chunker=Chunker(max_chars=max_chars),
        with_callers=with_callers,
        with_callees=with_callees,
    )
    artifacts = source.list_artifacts()
    print(
        f"scanning {len(artifacts)} artifacts x up to {len(skills)} skills",
        file=sys.stderr,
    )
    agents, orchestrator = build_skill_orchestration(strategy, provider=provider, model=model, max_tokens=max_tokens)
    return run_over_artifacts_with_skills(
        artifacts, Selector(tuple(skills)), agents, orchestrator,
        cache=cache, orchestration=orchestration_descriptor(provider, strategy, model, max_tokens),
    )


def _render_dry_run(result: AnalysisResult) -> str:
    lines = [f"observations: {len(result.observations)}"]
    for o in result.observations:
        lines.append(f"  [{o.kind}] {o.capability} by {o.produced_by} -> {getattr(o, 'status', '-')}")
    if result.error:
        lines.append(f"error: {result.error}")
    return "\n".join(lines)


def _render_audit(results: list[tuple[str, AnalysisResult]]) -> str:
    if not results:
        return "no changed files in diff"
    lines = []
    for path, result in results:
        lines.append(f"== {path} ==")
        if result.error:
            lines.append(f"  error: {result.error}")
        for o in result.observations:
            lines.append("  " + _render_observation(o))
    return "\n".join(lines)


def _render_observation(o: Observation) -> str:
    if o.kind == "verdict":
        matched = o.matched_anti or o.matched_correct
        suffix = f" [{', '.join(matched)}]" if matched else ""
        return f"{o.status:<11} {o.capability}{suffix}"
    if o.kind == "finding":
        cwe = f" {o.cwe}" if o.cwe else ""
        return f"{'FINDING':<11} [{o.severity}{cwe}] {o.title}"
    if o.kind == "concession":
        return f"{'DISMISSED':<11} {o.target}: {o.reason}"
    return f"{o.kind}: {o.capability}"


def _render_results(fmt: str, results: list[tuple[str, AnalysisResult]]) -> str:
    return {"text": _render_audit, "markdown": to_markdown, "json": to_json, "sarif": to_sarif}[fmt](results)


def _maybe_suppress(results: list[tuple[str, AnalysisResult]], enabled: bool) -> list[tuple[str, AnalysisResult]]:
    if not enabled:
        return results
    filtered, suppressed = filter_results(results, load_suppressions(SUPPRESSIONS_FILE))
    if suppressed:
        print(f"suppressed {len(suppressed)} known-noise finding(s) by rule", file=sys.stderr)
    return filtered


def _maybe_baseline(results: list[tuple[str, AnalysisResult]], baseline_path: str | None) -> list[tuple[str, AnalysisResult]]:
    if not baseline_path:
        return results
    try:
        with open(baseline_path, encoding="utf-8") as f:
            baseline = from_json(f.read())
    except Exception as exc:
        print(f"could not read baseline {baseline_path!r}: {exc}; reporting all findings", file=sys.stderr)
        return results
    filtered, dropped = filter_new(results, baseline)
    if dropped:
        print(f"baseline: hid {dropped} pre-existing finding(s)", file=sys.stderr)
    return filtered

_FAIL_ON = ("critical", "high", "medium", "low")
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _problem_rank(o: Observation) -> int:
    if o.kind == "finding":
        return _SEVERITY_RANK.get(o.severity.lower(), 2)
    if o.kind == "verdict" and o.status == "VULNERABLE":
        return _SEVERITY_RANK["high"]
    if o.kind == "verdict" and o.status == "PARTIAL":
        return _SEVERITY_RANK["medium"]
    return -1


def _gate_exit(results: list[tuple[str, AnalysisResult]], fail_on: str | None) -> int:
    if not fail_on:
        return 0
    worst = max((_problem_rank(o) for _, r in results for o in r.observations), default=-1)
    return 1 if worst >= _SEVERITY_RANK[fail_on] else 0


def _maybe_post_github(ref: str | None, results: list[tuple[str, AnalysisResult]]) -> None:
    if not ref:
        return
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("GITHUB_TOKEN not set; skipping PR review", file=sys.stderr)
        return
    try:
        owner, repo, pull = parse_pr_ref(ref)
        post_review(owner, repo, pull, build_review(results), token=token)
        print(f"posted review to {ref}", file=sys.stderr)
    except Exception as exc:
        print(f"github review failed: {exc}", file=sys.stderr)


def _render_eval(report: EvalReport) -> str:
    def line(label: str, m) -> str:
        return (
            f"{label:<20} tp={m.tp} fp={m.fp} tn={m.tn} fn={m.fn}  "
            f"P={m.precision:.2f} R={m.recall:.2f} F1={m.f1:.2f}"
        )

    lines = [line(f"overall ({report.overall.total} cases)", report.overall)]
    lines += [line(cap, m) for cap, m in sorted(report.by_capability.items())]
    return "\n".join(lines)


def _read_diff(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as f:
        return f.read()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="codejury")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("dry-run", help="run the mock pipeline end to end")

    audit_p = sub.add_parser("audit", help="audit a unified diff against the skill library")
    audit_p.add_argument("diff", nargs="?", default="-", help="unified diff file, or - for stdin")
    audit_p.add_argument("--skills", default=SKILLS_DIR, help="skill directory")
    audit_p.add_argument("--orchestrator", choices=STRATEGIES, default="single")
    audit_p.add_argument("--provider", choices=PROVIDERS, default="anthropic")
    audit_p.add_argument("--format", choices=_FORMATS, default="text", dest="fmt")
    audit_p.add_argument("--model", default=DEFAULT_MODEL)
    audit_p.add_argument("--max-tokens", type=int, default=2048)
    audit_p.add_argument("--retries", type=int, default=0, help="provider retry attempts on failure")
    audit_p.add_argument("--api-base", default=DEFAULT_API_BASE, help="provider base URL (env: CODEJURY_API_BASE)")
    audit_p.add_argument("--api-key", default=DEFAULT_API_KEY, help="provider API key (env: CODEJURY_API_KEY)")
    audit_p.add_argument("--no-suppress", action="store_true", help="disable the known-noise suppression filter")
    audit_p.add_argument("--no-cache", action="store_true", help="bypass the verdict cache (always re-query the model)")
    audit_p.add_argument("--baseline", default=None, help="a prior JSON report; report only findings new since it")
    audit_p.add_argument("--fail-on", choices=_FAIL_ON, default=None, dest="fail_on", help="exit 1 if a finding at/above this severity is found")
    audit_p.add_argument("--github", default=None, help="post a PR review: owner/repo#number (needs GITHUB_TOKEN)")

    scan_p = sub.add_parser("scan", help="audit a whole directory tree, skill by skill")
    scan_p.add_argument("directory", help="directory to scan")
    scan_p.add_argument("--ext", default=".py", help="comma-separated file extensions (default .py)")
    scan_p.add_argument("--only", default=None, help="comma-separated skill ids to scan (default: all)")
    scan_p.add_argument("--skills", default=SKILLS_DIR, help="skill directory")
    scan_p.add_argument("--orchestrator", choices=STRATEGIES, default="pipeline")
    scan_p.add_argument("--provider", choices=PROVIDERS, default="anthropic")
    scan_p.add_argument("--format", choices=_FORMATS, default="text", dest="fmt")
    scan_p.add_argument("--model", default=DEFAULT_MODEL)
    scan_p.add_argument("--max-tokens", type=int, default=2048)
    scan_p.add_argument("--max-chars", type=int, default=200_000, help="chunk budget; default keeps whole files")
    scan_p.add_argument(
        "--callers", action="store_true", help="add cross-file context: where this file's functions are called"
    )
    scan_p.add_argument(
        "--callees", action="store_true", help="add cross-file context: the called code this file delegates to"
    )
    scan_p.add_argument("--api-base", default=DEFAULT_API_BASE, help="provider base URL (env: CODEJURY_API_BASE)")
    scan_p.add_argument("--api-key", default=DEFAULT_API_KEY, help="provider API key (env: CODEJURY_API_KEY)")
    scan_p.add_argument("--no-suppress", action="store_true", help="disable the known-noise suppression filter")
    scan_p.add_argument("--no-cache", action="store_true", help="bypass the verdict cache (always re-query the model)")
    scan_p.add_argument("--baseline", default=None, help="a prior JSON report; report only findings new since it")
    scan_p.add_argument("--retries", type=int, default=0, help="provider retry attempts on failure")
    scan_p.add_argument("--fail-on", choices=_FAIL_ON, default=None, dest="fail_on", help="exit 1 if a finding at/above this severity is found")

    run_p = sub.add_parser("run", help="run a named task preset against a unified diff")
    run_p.add_argument("task", help="task name")
    run_p.add_argument("diff", nargs="?", default="-", help="unified diff file, or - for stdin")
    run_p.add_argument("--tasks", default=TASKS_DIR, help="task YAML directory")
    run_p.add_argument("--skills", default=SKILLS_DIR, help="skill directory")
    run_p.add_argument("--format", choices=_FORMATS, default="text", dest="fmt")
    run_p.add_argument("--no-suppress", action="store_true", help="disable the known-noise suppression filter")
    run_p.add_argument("--no-cache", action="store_true", help="bypass the verdict cache (always re-query the model)")
    run_p.add_argument("--fail-on", choices=_FAIL_ON, default=None, dest="fail_on", help="exit 1 if a finding at/above this severity is found")

    eval_p = sub.add_parser("eval", help="score golden cases and report precision/recall")
    eval_p.add_argument("--dataset", default=GOLDEN_DIR, help="golden case YAML directory")
    eval_p.add_argument("--split", default=None, help="only score cases whose 'split' matches (e.g. held-out)")
    eval_p.add_argument("--orchestrator", choices=STRATEGIES, default="single")
    eval_p.add_argument("--skills", default=SKILLS_DIR, help="skill directory")
    eval_p.add_argument("--provider", choices=PROVIDERS, default="anthropic")
    eval_p.add_argument("--format", choices=("text", "json"), default="text", dest="fmt")
    eval_p.add_argument("--model", default=DEFAULT_MODEL)
    eval_p.add_argument("--api-base", default=DEFAULT_API_BASE, help="provider base URL (env: CODEJURY_API_BASE)")
    eval_p.add_argument("--api-key", default=DEFAULT_API_KEY, help="provider API key (env: CODEJURY_API_KEY)")
    eval_p.add_argument("--retries", type=int, default=0, help="provider retry attempts on failure")

    args = parser.parse_args(argv)
    try:
        return _dispatch(args, parser)
    except Exception as exc:
        # expected failures (missing diff file, provider auth, malformed input) become
        # one stderr line, not a traceback. eval's own message is preserved by command name.
        print(f"{args.command or 'codejury'} failed: {exc}", file=sys.stderr)
        return 1


def _dispatch(args, parser) -> int:
    if args.command == "audit":
        results = audit(
            _read_diff(args.diff),
            load_skills(args.skills),
            provider=make_provider(
                args.provider, api_key=args.api_key, api_base=args.api_base, retries=args.retries
            ),
            model=args.model,
            max_tokens=args.max_tokens,
            strategy=args.orchestrator,
            cache=None if args.no_cache else VerdictCache(),
        )
        results = _maybe_suppress(results, not args.no_suppress)
        results = _maybe_baseline(results, args.baseline)
        print(_render_results(args.fmt, results))
        _maybe_post_github(args.github, results)
        return _gate_exit(results, args.fail_on)

    if args.command == "scan":
        skills = load_skills(args.skills)
        if args.only:
            wanted = {x.strip() for x in args.only.split(",")}
            unknown = wanted - {s.id for s in skills}
            if unknown:
                print(f"warning: --only names unknown skill id(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            skills = [s for s in skills if s.id in wanted]
        extensions = tuple(e if e.startswith(".") else "." + e for e in args.ext.split(","))
        results = scan(
            args.directory,
            skills,
            provider=make_provider(args.provider, api_key=args.api_key, api_base=args.api_base, retries=args.retries),
            model=args.model,
            max_tokens=args.max_tokens,
            strategy=args.orchestrator,
            extensions=extensions,
            max_chars=args.max_chars,
            with_callers=args.callers,
            with_callees=args.callees,
            cache=None if args.no_cache else VerdictCache(),
        )
        results = _maybe_suppress(results, not args.no_suppress)
        results = _maybe_baseline(results, args.baseline)
        print(_render_results(args.fmt, results))
        return _gate_exit(results, args.fail_on)

    if args.command == "run":
        tasks = load_tasks(args.tasks)
        if args.task not in tasks:
            print(f"unknown task {args.task!r}; available: {', '.join(sorted(tasks)) or '(none)'}")
            return 1
        results = run_task(
            tasks[args.task],
            DiffSource(_read_diff(args.diff)),
            load_skills(args.skills),
            cache=None if args.no_cache else VerdictCache(),
        )
        results = _maybe_suppress(results, not args.no_suppress)
        print(_render_results(args.fmt, results))
        return _gate_exit(results, args.fail_on)

    if args.command == "eval":
        report = evaluate(
            load_cases(args.dataset, split=args.split),
            load_skills(args.skills),
            provider=make_provider(args.provider, api_key=args.api_key, api_base=args.api_base, retries=args.retries),
            model=args.model,
            strategy=args.orchestrator,
        )
        print(json.dumps(report.to_dict(), indent=2) if args.fmt == "json" else _render_eval(report))
        return 0

    if args.command in (None, "dry-run"):
        print(_render_dry_run(dry_run()))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
