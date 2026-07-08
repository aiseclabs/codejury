"""Web PoC writing for the web domain. For a candidate it writes a standalone Python script
that reproduces the exploit, so a web finding carries a concrete runnable recipe, not only a
prose scenario.

It writes, it does not run, invariant 6. A web exploit needs a live server, credentials, and
state, so running is human-in-the-loop against a sandbox or dev host, never automatic and never
production. `execute` therefore reports the PoC as unrun, it never sends a request itself.

It only adds evidence, it never refutes, invariant 2. A finding is kept whether or not a human
later runs the script, so a written but unrun PoC lowers nothing and drops nothing.
"""

from __future__ import annotations

import re

from codejury.domains.base import PoCArtifact, PoCExecResult
from codejury.providers.base import Message, Provider

_SYSTEM = (
    "You write a single self-contained Python script that reproduces one web application "
    "vulnerability. Use only the requests library and the standard library. Read the target base "
    "url from the BASE_URL environment variable and read any test credential from a named "
    "environment variable, so the script needs no other input. Perform the minimal steps, such as "
    "authenticating and then sending the exploit request, and assert that the exploit succeeded, "
    "for example that it read another user's resource or performed an action it must not. Never "
    "perform a destructive action and never target a production host. Respond with only the Python "
    "source of the script, no prose and no fences."
)

_RUN_HINT = "python the script, set BASE_URL to a sandbox or dev host, never production"


def _extract_python(text: str) -> str:
    """The Python body from a model reply, tolerating a fenced block or bare source."""
    fence = re.search(r"```(?:python)?\s*(.*?)```", text, re.DOTALL)
    return (fence.group(1) if fence else text).strip()


class WebPoC:
    """Write a candidate's exploit as a runnable Python script. It writes, a human runs it against
    a sandbox, invariant 6. Adds evidence, never refutes, invariant 2."""

    ext = "py"
    # the web domain never runs its PoC automatically, so the write step writes and the shared run
    # step reports it as manual rather than expecting a toolchain, unlike the evm forge backend
    executes = False

    def __init__(self, *, provider: Provider | None = None, model: str | None = None,
                 max_tokens: int = 4096) -> None:
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens

    def available(self) -> bool:
        """A web PoC is never executed automatically, so nothing here runs it, invariant 6."""
        return False

    def generate(self, *, title: str, analysis: str, symbol: str, file: str,
                 line: int | None, root: str) -> PoCArtifact:
        """Write the Python script that proves the exploit, without running it."""
        if self._provider is None:
            raise ValueError("generating a PoC needs a provider, this backend was built to run only")
        prompt = _prompt(title=title, analysis=analysis, symbol=symbol, file=file, line=line)
        reply = self._provider.complete(
            system=_SYSTEM, messages=[Message(role="user", content=prompt)],
            model=self._model, max_tokens=self._max_tokens, cache=False)
        return PoCArtifact(source=_extract_python(reply.text), ext=self.ext, run_hint=_RUN_HINT)

    def execute(self, *, source: str, root: str) -> PoCExecResult:
        """Report the web PoC as unrun. Running it hits a live server, so a human does that against
        a sandbox, this never sends a request, invariant 6."""
        return PoCExecResult(
            ran=False, ok=False,
            detail="a web PoC runs by hand against a sandbox, never automatically, invariant 6")


def _prompt(*, title: str, analysis: str, symbol: str, file: str, line: int | None) -> str:
    loc = f"{file}:{line}" if line else file
    return (
        f"Vulnerability: {title}\n"
        f"Location: {loc}\n"
        f"Function or handler: {symbol}\n"
        f"Analysis: {analysis}\n\n"
        "Write the script that reproduces this vulnerability against a running instance. It passes "
        "only when the exploit succeeds."
    )
