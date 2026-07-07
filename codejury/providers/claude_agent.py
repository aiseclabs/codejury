"""The headless `claude -p` transport, shared by every subscription backend.

A subscription seat runs a headless Claude Code agent via `claude -p` instead of calling
a vendor API, so it uses the operator's Claude Code access with no provider key or proxy
limit. The same transport serves both review paths: the repo backends in
`review/repo/agent.py` subclass `_ClaudeBackend` to read files themselves, and
`ClaudeAgentProvider` here is a drop-in `Provider` for the diff path, where the diff is
already in the prompt and no file tools are needed.

The exact `claude` invocation varies by version, so the binary and its args are
configurable, via the constructor or `CODEJURY_CLAUDE_BIN` / `CODEJURY_CLAUDE_ARGS`. The
prompt is fed on stdin so a large mandate does not hit the argv limit. The subprocess call
goes through an injected runner, so the backends are testable with no real `claude`.

The call runs through a `ClaudeTransport`, selected by `CODEJURY_CLAUDE_TRANSPORT`, so a
future persistent transport can amortize the Claude Code startup cost that today is paid on
every call, without touching the retry or fail-loud path. The default is `process`, one
`claude -p` per call. An injected runner still wins, so the tests keep their seam.

This module is a leaf: it imports only the standard library and `providers.base`, never
`review/` or `domains/`, so the transport sits at the provider layer and both paths depend
on it downward.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
from typing import Callable

from codejury.providers.base import CompletionResult, Message, Provider

_OUTPUT_ARGS = ("--output-format", "json")
READ_ONLY_TOOLS = ("--allowedTools", "Read,Grep,Glob,LS")
DEFAULT_CLAUDE_ARGS = (*_OUTPUT_ARGS, *READ_ONLY_TOOLS)
_UNSAFE_TOOLS_ENV = "CODEJURY_CLAUDE_UNSAFE_TOOLS"
# The nested `claude -p` must authenticate with the operator's Claude Code subscription, not an
# API key codejury carries for its own provider call. An inherited ANTHROPIC_API_KEY or base URL,
# stale or pointed at a proxy, makes the nested agent 401 instead of riding the subscription, so
# they are scrubbed from its environment.
_SCRUBBED_AUTH_ENV = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL")

Runner = Callable[..., str]


def _subscription_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k not in _SCRUBBED_AUTH_ENV}


def _drop_flag(args: tuple[str, ...], flag: str) -> tuple[str, ...]:
    out: list[str] = []
    it = iter(args)
    for a in it:
        if a == flag:
            next(it, None)
            continue
        out.append(a)
    return tuple(out)


def _compose_claude_args(extra: tuple[str, ...], *, unsafe: bool,
                         allowed_tools: tuple[str, ...] = READ_ONLY_TOOLS) -> tuple[str, ...]:
    """The effective `claude -p` args. `allowed_tools` is mandatory and substituted by the caller,
    the repo backends read files so they pass the read-only set, the diff provider answers from the
    prompt so it passes none. Extra args from `CODEJURY_CLAUDE_ARGS` or the constructor are appended,
    but any `--allowedTools` they carry is dropped, so a misconfigured environment cannot silently
    widen the tools. `CODEJURY_CLAUDE_UNSAFE_TOOLS=1` is the one explicit way to hand tool selection
    to the extra args."""
    if unsafe:
        return (*_OUTPUT_ARGS, *extra)
    return (*_OUTPUT_ARGS, *allowed_tools, *_drop_flag(extra, "--allowedTools"))


def _envelope_error(stdout: str) -> str | None:
    """An error reported inside a `--output-format json` envelope, or None.

    A rate-limited or failed `claude -p` can still exit 0 while the envelope carries
    `is_error` or a non-success subtype. Treating that as success silently turns a
    failed call into an empty clean result, the exact thing the fail-loud rule
    forbids, so the runner must detect it and raise."""
    try:
        env = json.loads(stdout.strip())
    except json.JSONDecodeError:
        return None
    if not isinstance(env, dict):
        return None
    if env.get("is_error") or env.get("api_error_status") or env.get("subtype", "success") != "success":
        return str(env.get("api_error_status") or env.get("subtype") or "is_error")
    return None


def _default_runner(prompt: str, *, cwd: str, claude_bin: str, args: tuple[str, ...], timeout: int) -> str:
    """Run `claude -p` headless with the prompt on stdin, return stdout, raise on error."""
    proc = subprocess.run(
        [claude_bin, "-p", *args],
        input=prompt, cwd=cwd or None, env=_subscription_env(),
        capture_output=True, text=True, timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"claude exited {proc.returncode}: {proc.stderr.strip()[:300]}")
    err = _envelope_error(proc.stdout)
    if err:
        raise RuntimeError(f"claude reported an error ({err}): {proc.stdout.strip()[:200]}")
    return proc.stdout


def _result_text(stdout: str) -> str:
    """Pull the assistant text out of `--output-format json`, or pass plain text through."""
    s = stdout.strip()
    try:
        env = json.loads(s)
        if isinstance(env, dict) and "result" in env:
            return str(env["result"])
    except json.JSONDecodeError:
        pass
    return s


_TRANSPORT_ENV = "CODEJURY_CLAUDE_TRANSPORT"


class ClaudeTransport:
    """One call equivalent to `claude -p`, behind the seam where a runner is injected.

    `ask` mirrors the `Runner` signature, so a transport drops into `_ClaudeBackend._ask`
    with no change to its retry or fail-loud path, and a test can still inject a plain runner
    instead. `close` releases any persistent session a transport holds, and does nothing for
    the stateless process transport. The tool policy travels inside `args`, already composed
    and guarded by `_compose_claude_args`, so a transport reads it rather than deriving it again.
    """

    def ask(self, prompt: str, *, cwd: str, claude_bin: str, args: tuple[str, ...],
            timeout: int) -> str:
        raise NotImplementedError

    def close(self) -> None:
        pass


class ProcessClaudeTransport(ClaudeTransport):
    """The default transport, one `claude -p` process per call, the historical behavior."""

    def ask(self, prompt: str, *, cwd: str, claude_bin: str, args: tuple[str, ...],
            timeout: int) -> str:
        return _default_runner(prompt, cwd=cwd, claude_bin=claude_bin, args=args, timeout=timeout)


def _resolve_transport(name: str | None = None) -> ClaudeTransport:
    """The transport named by `CODEJURY_CLAUDE_TRANSPORT`, `process` by default. An unknown
    value fails loud at construction rather than silently falling back to a working default,
    so a misconfigured transport cannot pass as a clean run, invariant 4."""
    name = name if name is not None else os.environ.get(_TRANSPORT_ENV, "process")
    if name == "process":
        return ProcessClaudeTransport()
    raise RuntimeError(f"unknown {_TRANSPORT_ENV} {name!r}, expected 'process'")


class _ClaudeBackend:
    def __init__(self, *, claude_bin: str | None = None, args: tuple[str, ...] | None = None,
                 timeout: int = 900, retries: int = 2, backoff: float = 10.0,
                 runner: Runner | None = None,
                 transport: ClaudeTransport | None = None,
                 allowed_tools: tuple[str, ...] = READ_ONLY_TOOLS) -> None:
        self._bin = claude_bin or os.environ.get("CODEJURY_CLAUDE_BIN", "claude")
        env_args = os.environ.get("CODEJURY_CLAUDE_ARGS")
        extra = tuple(shlex.split(env_args)) if env_args else (tuple(args) if args else ())
        unsafe = os.environ.get(_UNSAFE_TOOLS_ENV) == "1"
        self._args = _compose_claude_args(extra, unsafe=unsafe, allowed_tools=allowed_tools)
        self._timeout = timeout
        self._retries = retries
        self._backoff = backoff
        # An injected runner wins, the test seam. Otherwise a transport runs the call: the one
        # passed in, or the one CODEJURY_CLAUDE_TRANSPORT selects, process by default. The
        # transport is held so a persistent one can be closed at the end of a run.
        self._transport = None if runner is not None else (transport or _resolve_transport())
        self._runner = runner if runner is not None else self._transport.ask

    def _ask(self, prompt: str, cwd: str) -> str:
        """Run the agent, retrying with backoff, since a rate limit is usually transient.
        Raises the last error if every attempt fails, so the orchestrator counts it."""
        last: Exception | None = None
        for attempt in range(self._retries + 1):
            try:
                return self._runner(prompt, cwd=cwd, claude_bin=self._bin, args=self._args, timeout=self._timeout)
            except Exception as exc:
                last = exc
                if attempt < self._retries and self._backoff:
                    time.sleep(self._backoff * (attempt + 1))
        assert last is not None
        raise last

    def close(self) -> None:
        """Release the transport's persistent session, if any. It does nothing when a runner
        was injected or the transport is stateless, and is safe to call more than once."""
        if self._transport is not None:
            self._transport.close()


def _fold_prompt(system: str, messages: list[Message]) -> str:
    """Fold the system text and messages into one stdin prompt, since `claude -p` has no separate
    system channel. The system text leads so a 'respond with a single JSON object' instruction still
    governs the reply. A role label is added only when more than one message would be ambiguous, so
    the single-message diff calls stay verbatim."""
    parts: list[str] = []
    if system:
        parts.append(system)
    multi = len(messages) > 1
    for m in messages:
        parts.append(f"[{m.role}] {m.content}" if multi else m.content)
    return "\n\n".join(parts)


class ClaudeAgentProvider(_ClaudeBackend, Provider):
    """A Provider that answers through a headless `claude -p` agent on the operator's Claude Code
    subscription instead of a vendor API, so a path runs with no provider key. The diff is already
    in the prompt, so the agent takes no file tools. `model` is advisory, the subscription picks the
    model and no `--model` is passed. `cache` does not apply to a subprocess call. A blank or
    error-enveloped reply raises through `_ask`, never returns as an empty clean result."""

    def __init__(self, *, cwd: str = "", **kw) -> None:
        super().__init__(allowed_tools=(), **kw)
        self._cwd = cwd

    def complete(self, *, system: str, messages: list[Message], model: str, max_tokens: int,
                 cache: bool = False) -> CompletionResult:
        return CompletionResult(text=_result_text(self._ask(_fold_prompt(system, messages), self._cwd)))
