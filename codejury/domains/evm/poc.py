"""Forge PoC verification for the evm domain, behind the existing Verifier seam. For a
PoC-able candidate it will generate a Foundry test that demonstrates the exploit, then
compile and run it, turning a model claim into a reproduced fact. Behind the codejury[evm]
extra and a Foundry toolchain, availability is lazy-checked so importing the domain never
needs forge.

Safety is the hard contract, invariant 6. A PoC runs only against a local fork or a dev
node, never a production system. It never holds a real private key, never broadcasts a
transaction, and takes no destructive action without explicit operator approval.

The generation and run logic lands once Foundry is validated on a real target. Until then
this is the wired seam: it reports availability honestly and fails loud when asked to
verify without the tool, never silently confirming or refuting a finding, invariant 4.
"""

from __future__ import annotations

from shutil import which

from codejury.domains.base import BackendUnavailable
from codejury.review.repo.union import Candidate
from codejury.review.repo.verifier import Verdict, Verifier

_INSTALL_HINT = (
    "Foundry is not installed. The evm PoC verifier needs forge on PATH: install Foundry "
    "from https://getfoundry.sh, then re-run."
)


class ForgePoC(Verifier):
    """Confirm a candidate by reproducing its exploit in a Foundry test against a fork."""

    def available(self) -> bool:
        return which("forge") is not None

    def verify(self, candidate: Candidate, root: str) -> Verdict:
        if not self.available():
            raise BackendUnavailable(_INSTALL_HINT)
        raise NotImplementedError(
            "Forge PoC generation is not wired yet. The verifier seam is in place, the "
            "generation and fork run land once Foundry is validated on a real contract.")
