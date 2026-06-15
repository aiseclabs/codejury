"""Slither-backed facts for the evm domain, the seam that will ground contract review in a
call graph, storage layout, and per-function read and write sets. Behind the codejury[evm]
extra and a Solidity compiler, availability is lazy-checked so importing the domain never
needs the heavy dependency.

The extraction logic lands once the toolchain is validated on a real target. Until then
this is the wired seam: it reports availability honestly and fails loud when asked to work
without the tool, never a silent empty-facts pass that would read as a clean review,
invariant 3.
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
        raise NotImplementedError(
            "Slither fact extraction is not wired yet. The backend seam is in place, the "
            "extraction lands once the toolchain is validated on a real contract.")
