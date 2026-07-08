"""Forge PoC reproduction for the evm domain. For a candidate it generates a Foundry test
that demonstrates the exploit, then compiles and runs it locally, turning a model claim into
a run fact. Behind the codejury[evm] extra and a Foundry toolchain, availability is
lazy-checked so importing the domain never needs forge.

Safety is the hard contract, invariant 6. Tier one runs only locally: it never passes a fork
url or an rpc, never broadcasts, never holds a private key, and reverts to no network. Each
run is a throwaway temp project, killed on a timeout and removed after.

It only adds evidence, it never refutes, invariant 2. A finding is kept whether or not its PoC
reproduces, so a PoC that fails to compile or to trigger is recorded as inconclusive, never as
a safe verdict that could drop a real finding.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from shutil import which

from codejury.domains.base import BackendUnavailable
from codejury.providers.base import Message, Provider

_INSTALL_HINT = (
    "Foundry is not installed. The evm PoC backend needs forge on PATH: install Foundry "
    "from https://getfoundry.sh, then re-run."
)

_SYSTEM = (
    "You write a single self-contained Foundry test in Solidity that reproduces one smart "
    "contract vulnerability. The test runs locally with no fork, no rpc, and no external "
    "dependency. Do not import forge-std. Declare the cheatcode interface inline and use the "
    "cheatcode address 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D for vm. Import the contracts "
    "under test by their relative path under src. A public function whose name starts with "
    "test is a test case, and it must fail with a revert or a failing assertion when the "
    "vulnerability is present, so a passing run proves the exploit. Respond with only the "
    "Solidity source of the test file, no prose and no fences."
)


@dataclass(frozen=True)
class PoCResult:
    """The outcome of one reproduction attempt. `reproduced` is True only when the generated
    test compiled and passed, so a compile failure or a failing test is an inconclusive keep,
    never a refutation."""
    reproduced: bool
    test_source: str
    detail: str


def _extract_solidity(text: str) -> str:
    """The Solidity body from a model reply, tolerating a fenced block or bare source."""
    fence = re.search(r"```(?:solidity)?\s*(.*?)```", text, re.DOTALL)
    return (fence.group(1) if fence else text).strip()


class ForgePoC:
    """Reproduce a candidate's exploit in a local Foundry test. Local only, invariant 6. Adds
    evidence, never refutes, invariant 2."""

    def __init__(self, *, provider: Provider, model: str, timeout: int = 180,
                 max_tokens: int = 4096) -> None:
        self._provider = provider
        self._model = model
        self._timeout = timeout
        self._max_tokens = max_tokens

    def available(self) -> bool:
        return which("forge") is not None

    def reproduce(self, *, title: str, analysis: str, symbol: str, file: str,
                  line: int | None, root: str) -> PoCResult:
        if not self.available():
            raise BackendUnavailable(_INSTALL_HINT)
        sources = sorted(Path(root).rglob("*.sol"))
        if not sources:
            return PoCResult(reproduced=False, test_source="", detail="no Solidity sources under the target")
        target = _read(Path(root) / file) if file else ""
        prompt = _prompt(title=title, analysis=analysis, symbol=symbol, file=file,
                         line=line, target_source=target,
                         contract_paths=[str(p.relative_to(root)) for p in sources])
        reply = self._provider.complete(
            system=_SYSTEM, messages=[Message(role="user", content=prompt)],
            model=self._model, max_tokens=self._max_tokens, cache=False)
        test_source = _extract_solidity(reply.text)
        if not test_source:
            return PoCResult(reproduced=False, test_source="", detail="model returned no test source")
        ok, detail = self._build_and_test(Path(root), sources, test_source)
        return PoCResult(reproduced=ok, test_source=test_source, detail=detail)

    def _build_and_test(self, root: Path, sources: list[Path], test_source: str) -> tuple[bool, str]:
        """Compile and run the generated test in a throwaway local project. Never forks, never
        broadcasts, invariant 6."""
        with tempfile.TemporaryDirectory(prefix="codejury-poc-") as tmp:
            proj = Path(tmp)
            (proj / "foundry.toml").write_text(
                "[profile.default]\nsrc = 'src'\ntest = 'test'\nauto_detect_solc = true\n",
                encoding="utf-8")
            src = proj / "src"
            for s in sources:
                dest = src / s.relative_to(root)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(s, dest)
            (proj / "test").mkdir()
            (proj / "test" / "PoC.t.sol").write_text(test_source, encoding="utf-8")
            build = self._forge(["build"], proj)
            if build.returncode != 0:
                return False, f"compile failed: {_tail(build.stdout + build.stderr)}"
            # no --fork-url, no --rpc-url, no --broadcast, invariant 6
            run = self._forge(["test", "--match-path", "test/PoC.t.sol"], proj)
            if run.returncode == 0:
                return True, "PoC compiled and passed, exploit reproduced"
            return False, f"PoC ran but did not pass: {_tail(run.stdout + run.stderr)}"

    def _forge(self, args: list[str], cwd: Path) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                ["forge", *args], cwd=cwd, capture_output=True, text=True,
                timeout=self._timeout, check=False)
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(args, returncode=1, stdout="", stderr="forge timed out")


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def _tail(text: str, limit: int = 800) -> str:
    text = text.strip()
    return text[-limit:] if len(text) > limit else text


def _prompt(*, title: str, analysis: str, symbol: str, file: str, line: int | None,
            target_source: str, contract_paths: list[str]) -> str:
    paths = "\n".join(f"- src/{p}" for p in contract_paths)
    loc = f"{file}:{line}" if line else file
    return (
        f"Vulnerability: {title}\n"
        f"Location: {loc}\n"
        f"Function or symbol: {symbol}\n"
        f"Analysis: {analysis}\n\n"
        f"Contracts available under src:\n{paths}\n\n"
        f"Source of the file under test ({file}):\n{target_source}\n\n"
        "Write test/PoC.t.sol that deploys the relevant contract and proves this "
        "vulnerability. Import contracts by their src-relative path. The test passes only "
        "when the exploit succeeds."
    )
