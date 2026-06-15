"""Slither-backed facts for the evm domain, grounding contract review in a call graph,
storage layout, and per-function read and write sets. Behind the codejury[evm] extra and a
Solidity compiler, availability is lazy-checked so importing the domain never needs the
heavy dependency, and slither itself is imported only inside extract.

A backend that cannot run fails loud rather than returning empty facts that would read as a
clean review, invariant 3. A missing toolchain raises BackendUnavailable, a compile error
in the target propagates as the native slither error.
"""

from __future__ import annotations

from importlib.util import find_spec
from pathlib import Path

from codejury.domains.base import BackendUnavailable, Facts, FactsBackend

_INSTALL_HINT = (
    "Slither is not installed. The evm facts backend needs the optional dependency and a "
    "Solidity compiler: pip install 'codejury[evm]', and install solc or foundry."
)


class SlitherFacts(FactsBackend):
    """Extract a call graph, storage layout, and read and write sets with Slither."""

    def available(self) -> bool:
        return find_spec("slither") is not None

    def extract(self, root: str | Path) -> Facts:
        if not self.available():
            raise BackendUnavailable(_INSTALL_HINT)
        from slither import Slither
        from slither.slithir.operations import InternalCall

        sl = Slither(str(root))
        contracts: dict = {}
        for c in sl.contracts:
            if c.is_interface:
                continue
            functions: dict = {}
            for f in c.functions_declared:
                # skip the pseudo functions slither synthesizes for state variable initializers
                if f.name.startswith("slitherConstructor"):
                    continue
                callees = sorted({
                    op.function.full_name
                    for op in f.internal_calls
                    if isinstance(op, InternalCall) and op.function is not None
                })
                functions[f.full_name] = {
                    "visibility": f.visibility,
                    "modifiers": [m.name for m in f.modifiers],
                    "reads": sorted(v.name for v in f.state_variables_read),
                    "writes": sorted(v.name for v in f.state_variables_written),
                    "calls": callees,
                    "external_call": bool(f.high_level_calls or f.low_level_calls),
                    "sends_eth": f.can_send_eth(),
                    "can_reenter": f.can_reenter(),
                }
            contracts[c.name] = {
                "state": [{"name": v.name, "type": str(v.type)} for v in c.state_variables],
                "functions": functions,
            }
        data = {"contracts": contracts}
        return Facts(summary=_render(contracts), data=data)


def _render(contracts: dict) -> str:
    """A compact, model-readable rendering of the facts, one block per contract. It leads
    with the storage layout, then a line per function carrying only the flags that hold, so
    the reentrancy, access-control, and accounting signals are visible without the model
    rereading the whole tree."""
    lines: list[str] = []
    for name, c in contracts.items():
        lines.append(f"contract {name}")
        if c["state"]:
            state = ", ".join(f"{v['name']} {v['type']}" for v in c["state"])
            lines.append(f"  state: {state}")
        for fn, info in c["functions"].items():
            flags: list[str] = []
            if info["reads"]:
                flags.append(f"reads[{','.join(info['reads'])}]")
            if info["writes"]:
                flags.append(f"writes[{','.join(info['writes'])}]")
            if info["calls"]:
                flags.append(f"calls[{','.join(info['calls'])}]")
            if info["external_call"]:
                flags.append("ext-call")
            if info["sends_eth"]:
                flags.append("sends-eth")
            if info["can_reenter"]:
                flags.append("reenter")
            mods = f" [{','.join(info['modifiers'])}]" if info["modifiers"] else ""
            lines.append(f"  {info['visibility']} {fn}{mods}  {' '.join(flags)}".rstrip())
    return "\n".join(lines)
