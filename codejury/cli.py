"""Command-line entry point.

For Phase 0 it offers a single ``dry-run`` that wires every mock layer together
(source -> orchestrator -> agent -> provider) and prints the AnalysisResult,
proving the contracts compose with no API key.
"""

from __future__ import annotations

import argparse

from codejury.agents.mock import MockAgent
from codejury.domain.capability import Capability
from codejury.domain.context import AnalysisContext
from codejury.domain.result import AnalysisResult
from codejury.orchestrators.mock import MockOrchestrator
from codejury.providers.mock import MockProvider
from codejury.sources.mock import MockSource


def dry_run() -> AnalysisResult:
    source = MockSource()
    provider = MockProvider(default="[mock] no real backend was called")
    agent = MockAgent(provider=provider, role="verifier")
    orchestrator = MockOrchestrator()
    capabilities = [
        Capability(id="authn", name="Authentication"),
        Capability(id="crypto", name="Cryptography"),
    ]

    observations = []
    for artifact in source.list_artifacts():
        ctx = AnalysisContext(artifact=artifact, capabilities=capabilities)
        observations.extend(orchestrator.run({"verifier": agent}, ctx).observations)
    return AnalysisResult(observations=observations)


def _render(result: AnalysisResult) -> str:
    lines = [f"observations: {len(result.observations)}"]
    for o in result.observations:
        status = getattr(o, "status", "-")
        lines.append(f"  [{o.kind}] {o.capability} by {o.produced_by} -> {status}")
    if result.error:
        lines.append(f"error: {result.error}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="codejury")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("dry-run", help="run the mock pipeline end to end")
    args = parser.parse_args(argv)

    if args.command in (None, "dry-run"):
        print(_render(dry_run()))
        return 0
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
