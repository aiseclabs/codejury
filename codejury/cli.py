"""Command-line entry point.

``dry-run`` wires every mock layer together with no API key, proving the
contracts compose. ``audit`` runs the real pipeline against the capability
library, backed by the Anthropic provider, under a chosen orchestration strategy
(single verifier, or finder/challenger/judge debate).
"""

from __future__ import annotations

import argparse
import sys

from codejury.assembly import (
    DEFAULT_MODEL,
    PROVIDERS,
    STRATEGIES,
    build_orchestration,
    make_provider,
    run_over_source,
)
from codejury.agents.mock import MockAgent
from codejury.domain.artifact import CodeArtifact
from codejury.domain.capability import Capability, load_capabilities
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Observation
from codejury.domain.result import AnalysisResult
from codejury.orchestrators.single import SingleOrchestrator
from codejury.providers.base import Provider
from codejury.providers.mock import MockProvider
from codejury.reporting import to_json, to_markdown
from codejury.sources.diff import DiffSource
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
    audit_p.add_argument("--capabilities", default="capabilities", help="capability YAML directory")
    audit_p.add_argument("--orchestrator", choices=STRATEGIES, default="single")
    audit_p.add_argument("--provider", choices=PROVIDERS, default="anthropic")
    audit_p.add_argument("--format", choices=_FORMATS, default="text", dest="fmt")
    audit_p.add_argument("--model", default=DEFAULT_MODEL)
    audit_p.add_argument("--max-tokens", type=int, default=2048)
    audit_p.add_argument("--retries", type=int, default=0, help="provider retry attempts on failure")

    run_p = sub.add_parser("run", help="run a named task preset against a unified diff")
    run_p.add_argument("task", help="task name")
    run_p.add_argument("diff", nargs="?", default="-", help="unified diff file, or - for stdin")
    run_p.add_argument("--tasks", default="tasks", help="task YAML directory")
    run_p.add_argument("--capabilities", default="capabilities", help="capability YAML directory")
    run_p.add_argument("--format", choices=_FORMATS, default="text", dest="fmt")

    args = parser.parse_args(argv)

    if args.command == "audit":
        results = audit(
            _read_diff(args.diff),
            load_capabilities(args.capabilities),
            provider=make_provider(args.provider, retries=args.retries),
            model=args.model,
            max_tokens=args.max_tokens,
            strategy=args.orchestrator,
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

    if args.command in (None, "dry-run"):
        print(_render_dry_run(dry_run()))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
