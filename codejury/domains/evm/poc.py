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

import os
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
    "You write a single Foundry test in Solidity that reproduces one smart contract "
    "vulnerability. The test runs locally with no fork, no rpc, and no broadcast. Declare the "
    "cheatcode interface inline and use the cheatcode address "
    "0x7109709ECfa91a80626fF3989D68f67F5b1DD12D for vm, do not import forge-std. Import the "
    "contract under test with the exact import line given to you. A public function whose name "
    "starts with test is a test case, and it must pass only when the exploit succeeds, so use a "
    "revert or a failing assertion for the safe case. Respond with only the Solidity source of "
    "the test file, no prose and no fences."
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
        root_p = Path(root)
        sources = sorted(root_p.rglob("*.sol"))
        if not sources:
            return PoCResult(reproduced=False, test_source="", detail="no Solidity sources under the target")
        foundry = (root_p / "foundry.toml").is_file()
        target = _read(root_p / file) if file else ""
        if foundry:
            # the test lives in the repo's own test dir, so it compiles through the repo's
            # remappings and restored libraries, the only way a contract that imports OpenZeppelin builds
            import_line = os.path.relpath(root_p / file, root_p / "test") if file else ""
            note = ("This is a Foundry project. Import other libraries such as OpenZeppelin through "
                    "the project's own remappings, for example \"openzeppelin/...\".")
        else:
            import_line = f"../src/{file}" if file else ""
            note = "The contracts are copied under src, import any dependency by its src-relative path."
        prompt = _prompt(title=title, analysis=analysis, symbol=symbol, file=file, line=line,
                         target_source=target, import_line=import_line, note=note)
        reply = self._provider.complete(
            system=_SYSTEM, messages=[Message(role="user", content=prompt)],
            model=self._model, max_tokens=self._max_tokens, cache=False)
        test_source = _extract_solidity(reply.text)
        if not test_source:
            return PoCResult(reproduced=False, test_source="", detail="model returned no test source")
        if foundry:
            ok, detail = self._build_in_repo(root_p, test_source)
        else:
            ok, detail = self._build_flat(root_p, sources, test_source)
        return PoCResult(reproduced=ok, test_source=test_source, detail=detail)

    def _build_in_repo(self, root: Path, test_source: str) -> tuple[bool, str]:
        """Reproduce inside a copy of the real Foundry project so its own config, remappings, and
        libraries resolve, the only way a contract with external dependencies compiles. Restores
        missing submodule libraries first. Never forks or broadcasts, invariant 6."""
        with tempfile.TemporaryDirectory(prefix="codejury-poc-") as tmp:
            proj = Path(tmp) / "repo"
            shutil.copytree(root, proj, ignore=shutil.ignore_patterns("out", "cache", "node_modules"))
            lib = proj / "lib"
            if (proj / ".gitmodules").is_file() and not (lib.is_dir() and any(lib.iterdir())):
                self._forge(["install"], proj)  # restore the submodule libraries, needs network
            (proj / "test").mkdir(exist_ok=True)
            (proj / "test" / "CodejuryPoC.t.sol").write_text(test_source, encoding="utf-8")
            return self._compile_and_run(proj, "test/CodejuryPoC.t.sol")

    def _build_flat(self, root: Path, sources: list[Path], test_source: str) -> tuple[bool, str]:
        """Reproduce in a throwaway bare project for a repo with no foundry config whose sources
        need no external library, such as a flat contracts directory. Never forks, invariant 6."""
        with tempfile.TemporaryDirectory(prefix="codejury-poc-") as tmp:
            proj = Path(tmp)
            (proj / "foundry.toml").write_text(
                "[profile.default]\nsrc = 'src'\ntest = 'test'\nauto_detect_solc = true\n",
                encoding="utf-8")
            for s in sources:
                dest = proj / "src" / s.relative_to(root)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(s, dest)
            (proj / "test").mkdir()
            (proj / "test" / "PoC.t.sol").write_text(test_source, encoding="utf-8")
            return self._compile_and_run(proj, "test/PoC.t.sol")

    def _compile_and_run(self, proj: Path, test_path: str) -> tuple[bool, str]:
        build = self._forge(["build"], proj)
        if build.returncode != 0:
            return False, f"compile failed: {_tail(build.stdout + build.stderr)}"
        # no --fork-url, no --rpc-url, no --broadcast, invariant 6
        run = self._forge(["test", "--match-path", test_path], proj)
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
            target_source: str, import_line: str, note: str) -> str:
    loc = f"{file}:{line}" if line else file
    return (
        f"Vulnerability: {title}\n"
        f"Location: {loc}\n"
        f"Function or symbol: {symbol}\n"
        f"Analysis: {analysis}\n\n"
        f"Import the contract under test with exactly:\nimport \"{import_line}\";\n"
        f"{note}\n\n"
        f"Source of the file under test ({file}):\n{target_source}\n\n"
        "Write the test that deploys the relevant contract and proves this vulnerability. "
        "The test passes only when the exploit succeeds."
    )
