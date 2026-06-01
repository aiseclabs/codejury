"""Command-line entry point.

``dry-run`` wires every mock layer together with no API key, proving the
contracts compose. ``audit`` runs the real pipeline against the capability
library, backed by the Anthropic provider, under a chosen orchestration strategy
(single verifier, or finder/challenger/judge debate).
"""

from __future__ import annotations

import argparse
import sys

from codejury.agents.mock import MockAgent
from codejury.assembly import (
    DEFAULT_API_BASE,
    DEFAULT_API_KEY,
    DEFAULT_MODEL,
    PROVIDERS,
    STRATEGIES,
    build_orchestration,
    make_provider,
    run_over_artifacts,
    run_over_source,
)
from codejury.domain.artifact import CodeArtifact
from codejury.domain.capability import Capability, load_capabilities
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Observation
from codejury.domain.result import AnalysisResult
from codejury.evaluation import Metrics, evaluate, load_cases
from codejury.orchestrators.single import SingleOrchestrator
from codejury.providers.base import Provider
from codejury.providers.mock import MockProvider
from codejury.reporting import to_json, to_markdown
from codejury.resources import CAPABILITIES_DIR, GOLDEN_DIR, TASKS_DIR
from codejury.sources.chunker import Chunker
from codejury.sources.diff import DiffSource
from codejury.sources.repo import RepoSource
from codejury.tasks.base import run_task
from codejury.tasks.registry import load_tasks

_FORMATS = ("text", "markdown", "json")


def dry_run() -> AnalysisResult:
    provider = MockProvider(default="[mock] no real backend was called")
    agent = MockAgent(provider=provider, role="verifier")
    orchestrator = SingleOrchestrator()
    capabilities = [
        Capability(id="authn", name="Authentication"),
        Capability(id="crypto", name="Cryptography"),
    ]
    ctx = AnalysisContext(
        artifact=CodeArtifact(kind="diff", path="auth.py", content="+ hashlib.sha256(pwd)"),
        capabilities=capabilities,
    )
    return orchestrator.run({"verifier": agent}, ctx)


def audit(
    diff_text: str,
    capabilities: list[Capability],
    *,
    provider: Provider,
    model: str,
    max_tokens: int = 2048,
    strategy: str = "single",
) -> list[tuple[str, AnalysisResult]]:
    """Audit each changed file in `diff_text`, returning (path, result) per file."""
    agents, orchestrator = build_orchestration(strategy, provider=provider, model=model, max_tokens=max_tokens)
    return run_over_source(DiffSource(diff_text), capabilities, agents, orchestrator)


def scan(
    directory: str,
    capabilities: list[Capability],
    *,
    provider: Provider,
    model: str,
    max_tokens: int = 2048,
    strategy: str = "pipeline",
    extensions: tuple[str, ...] = (".py",),
    max_chars: int = 200_000,
    with_callers: bool = False,
) -> list[tuple[str, AnalysisResult]]:
    """Audit every matching file in a directory tree, returning (path, result) per artifact."""
    source = RepoSource(
        directory, extensions=extensions, chunker=Chunker(max_chars=max_chars), with_callers=with_callers
    )
    artifacts = source.list_artifacts()
    calls = len(artifacts) * len(capabilities)
    print(
        f"scanning {len(artifacts)} artifacts x {len(capabilities)} capabilities (~{calls} model calls)",
        file=sys.stderr,
    )
    agents, orchestrator = build_orchestration(strategy, provider=provider, model=model, max_tokens=max_tokens)
    return run_over_artifacts(artifacts, capabilities, agents, orchestrator)


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
    return {"text": _render_audit, "markdown": to_markdown, "json": to_json}[fmt](results)


def _render_metrics(m: Metrics) -> str:
    return (
        f"cases: {m.total}  (tp={m.tp} fp={m.fp} tn={m.tn} fn={m.fn})\n"
        f"precision: {m.precision:.2f}  recall: {m.recall:.2f}  accuracy: {m.accuracy:.2f}"
    )


def _read_diff(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as f:
        return f.read()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="codejury")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("dry-run", help="run the mock pipeline end to end")

    audit_p = sub.add_parser("audit", help="audit a unified diff against the capability library")
    audit_p.add_argument("diff", nargs="?", default="-", help="unified diff file, or - for stdin")
    audit_p.add_argument("--capabilities", default=CAPABILITIES_DIR, help="capability YAML directory")
    audit_p.add_argument("--orchestrator", choices=STRATEGIES, default="single")
    audit_p.add_argument("--provider", choices=PROVIDERS, default="anthropic")
    audit_p.add_argument("--format", choices=_FORMATS, default="text", dest="fmt")
    audit_p.add_argument("--model", default=DEFAULT_MODEL)
    audit_p.add_argument("--max-tokens", type=int, default=2048)
    audit_p.add_argument("--retries", type=int, default=0, help="provider retry attempts on failure")
    audit_p.add_argument("--api-base", default=DEFAULT_API_BASE, help="provider base URL (env: CODEJURY_API_BASE)")
    audit_p.add_argument("--api-key", default=DEFAULT_API_KEY, help="provider API key (env: CODEJURY_API_KEY)")

    scan_p = sub.add_parser("scan", help="audit a whole directory tree (deep, capability by capability)")
    scan_p.add_argument("directory", help="directory to scan")
    scan_p.add_argument("--ext", default=".py", help="comma-separated file extensions (default .py)")
    scan_p.add_argument("--only", default=None, help="comma-separated capability ids to scan (default: all)")
    scan_p.add_argument("--capabilities", default=CAPABILITIES_DIR, help="capability YAML directory")
    scan_p.add_argument("--orchestrator", choices=STRATEGIES, default="pipeline")
    scan_p.add_argument("--provider", choices=PROVIDERS, default="anthropic")
    scan_p.add_argument("--format", choices=_FORMATS, default="text", dest="fmt")
    scan_p.add_argument("--model", default=DEFAULT_MODEL)
    scan_p.add_argument("--max-tokens", type=int, default=2048)
    scan_p.add_argument("--max-chars", type=int, default=200_000, help="chunk budget; default keeps whole files")
    scan_p.add_argument(
        "--callers", action="store_true", help="add cross-file call sites as context (cuts taint false positives)"
    )
    scan_p.add_argument("--api-base", default=DEFAULT_API_BASE, help="provider base URL (env: CODEJURY_API_BASE)")
    scan_p.add_argument("--api-key", default=DEFAULT_API_KEY, help="provider API key (env: CODEJURY_API_KEY)")

    run_p = sub.add_parser("run", help="run a named task preset against a unified diff")
    run_p.add_argument("task", help="task name")
    run_p.add_argument("diff", nargs="?", default="-", help="unified diff file, or - for stdin")
    run_p.add_argument("--tasks", default=TASKS_DIR, help="task YAML directory")
    run_p.add_argument("--capabilities", default=CAPABILITIES_DIR, help="capability YAML directory")
    run_p.add_argument("--format", choices=_FORMATS, default="text", dest="fmt")

    eval_p = sub.add_parser("eval", help="score golden cases and report precision/recall")
    eval_p.add_argument("--golden", default=GOLDEN_DIR, help="golden case YAML directory")
    eval_p.add_argument("--capabilities", default=CAPABILITIES_DIR, help="capability YAML directory")
    eval_p.add_argument("--provider", choices=PROVIDERS, default="anthropic")
    eval_p.add_argument("--model", default=DEFAULT_MODEL)
    eval_p.add_argument("--api-base", default=DEFAULT_API_BASE, help="provider base URL (env: CODEJURY_API_BASE)")
    eval_p.add_argument("--api-key", default=DEFAULT_API_KEY, help="provider API key (env: CODEJURY_API_KEY)")

    args = parser.parse_args(argv)

    if args.command == "audit":
        results = audit(
            _read_diff(args.diff),
            load_capabilities(args.capabilities),
            provider=make_provider(
                args.provider, api_key=args.api_key, api_base=args.api_base, retries=args.retries
            ),
            model=args.model,
            max_tokens=args.max_tokens,
            strategy=args.orchestrator,
        )
        print(_render_results(args.fmt, results))
        return 0

    if args.command == "scan":
        capabilities = load_capabilities(args.capabilities)
        if args.only:
            wanted = {x.strip() for x in args.only.split(",")}
            capabilities = [c for c in capabilities if c.id in wanted]
        extensions = tuple(e if e.startswith(".") else "." + e for e in args.ext.split(","))
        results = scan(
            args.directory,
            capabilities,
            provider=make_provider(args.provider, api_key=args.api_key, api_base=args.api_base),
            model=args.model,
            max_tokens=args.max_tokens,
            strategy=args.orchestrator,
            extensions=extensions,
            max_chars=args.max_chars,
            with_callers=args.callers,
        )
        print(_render_results(args.fmt, results))
        return 0

    if args.command == "run":
        tasks = load_tasks(args.tasks)
        if args.task not in tasks:
            print(f"unknown task {args.task!r}; available: {', '.join(sorted(tasks)) or '(none)'}")
            return 1
        results = run_task(
            tasks[args.task], DiffSource(_read_diff(args.diff)), load_capabilities(args.capabilities)
        )
        print(_render_results(args.fmt, results))
        return 0

    if args.command == "eval":
        try:
            metrics = evaluate(
                load_cases(args.golden),
                load_capabilities(args.capabilities),
                provider=make_provider(args.provider, api_key=args.api_key, api_base=args.api_base),
                model=args.model,
            )
        except Exception as exc:
            # e.g. a missing API key surfaces as a provider auth error -- report it
            # as one line, not a traceback (audit gets this via the orchestrator).
            print(f"eval failed: {exc}")
            return 1
        print(_render_metrics(metrics))
        return 0

    if args.command in (None, "dry-run"):
        print(_render_dry_run(dry_run()))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
