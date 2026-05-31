"""Command-line entry point.

``dry-run`` wires every mock layer together with no API key, proving the
contracts compose. ``audit`` runs the real pipeline against the capability
library, backed by the Anthropic provider, under a chosen orchestration strategy
(single verifier, or finder/challenger/judge debate).
"""

from __future__ import annotations

import argparse
import os
import sys

from codejury.agents.base import Agent
from codejury.agents.debate import ChallengerAgent, FinderAgent, JudgeAgent
from codejury.agents.mock import MockAgent
from codejury.agents.verifier import VerifierAgent
from codejury.domain.artifact import CodeArtifact
from codejury.domain.capability import Capability, load_capabilities
from codejury.domain.context import AnalysisContext
from codejury.domain.observation import Observation
from codejury.domain.result import AnalysisResult
from codejury.orchestrators.base import Orchestrator
from codejury.orchestrators.debate import DebateOrchestrator
from codejury.orchestrators.pipeline import PipelineOrchestrator
from codejury.orchestrators.single import SingleOrchestrator
from codejury.providers.anthropic import AnthropicProvider
from codejury.providers.base import Provider
from codejury.providers.mock import MockProvider
from codejury.sources.diff import DiffSource

_STRATEGIES = ("single", "pipeline", "debate")

_DEFAULT_MODEL = os.environ.get("CODEJURY_MODEL", "claude-sonnet-4-6")


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
    agents, orchestrator = _assemble(strategy, provider=provider, model=model, max_tokens=max_tokens)
    results = []
    for artifact in DiffSource(diff_text).list_artifacts():
        ctx = AnalysisContext(artifact=artifact, capabilities=capabilities)
        results.append((artifact.path, orchestrator.run(agents, ctx)))
    return results


def _assemble(
    strategy: str, *, provider: Provider, model: str, max_tokens: int
) -> tuple[dict[str, Agent], Orchestrator]:
    if strategy == "debate":
        roles = (FinderAgent, ChallengerAgent, JudgeAgent)
        agents = {cls.role: cls(provider=provider, model=model, max_tokens=max_tokens) for cls in roles}
        return agents, DebateOrchestrator()
    verifier = {"verifier": VerifierAgent(provider=provider, model=model, max_tokens=max_tokens)}
    if strategy == "pipeline":
        return verifier, PipelineOrchestrator()
    return verifier, SingleOrchestrator()


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
    audit_p.add_argument("--orchestrator", choices=_STRATEGIES, default="single")
    audit_p.add_argument("--model", default=_DEFAULT_MODEL)
    audit_p.add_argument("--max-tokens", type=int, default=2048)

    args = parser.parse_args(argv)

    if args.command == "audit":
        results = audit(
            _read_diff(args.diff),
            load_capabilities(args.capabilities),
            provider=AnthropicProvider(),
            model=args.model,
            max_tokens=args.max_tokens,
            strategy=args.orchestrator,
        )
        print(_render_audit(results))
        return 0

    if args.command in (None, "dry-run"):
        print(_render_dry_run(dry_run()))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
