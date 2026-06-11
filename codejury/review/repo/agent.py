"""Claude-CLI backends for the reviewer and verifier.

A per-unit review and a per-candidate verification, each run as a headless Claude
Code agent via `claude -p`. Two wins over the single grounded model call: it uses the
operator's Claude Code access, no provider key or proxy limit, and each call is a
real tool-using agent that reads the files itself and traces across them, the depth
that reached full recall in testing. The coded orchestration around it, the worklist,
the passes, the union, the verification, is unchanged.

The exact `claude` invocation varies by version, so the binary and its args are
configurable, via the constructor or `CODEJURY_CLAUDE_BIN` / `CODEJURY_CLAUDE_ARGS`.
The prompt is fed on stdin so a large mandate does not hit the argv limit. The
subprocess call goes through an injected runner, so the backends are testable with no
real `claude`.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
from typing import Callable

from codejury.json_parse import optional_json_object, require_json_object
from codejury.resources import FALSE_POSITIVE_TRAPS_FILE, SEVERITY_RUBRIC_FILE, UNIT_REVIEW_FILE
from codejury.review.repo.reviewer import (
    RepoReviewError,
    Unit,
    UnitReviewer,
    candidates_from_obj,
)
from codejury.review.repo.shapes import JSON_SHAPE, lens_line
from codejury.review.repo.union import Candidate
from codejury.review.repo.verifier import Verdict, Verifier

_OUTPUT_ARGS = ("--output-format", "json")
READ_ONLY_TOOLS = ("--allowedTools", "Read,Grep,Glob,LS")
DEFAULT_CLAUDE_ARGS = (*_OUTPUT_ARGS, *READ_ONLY_TOOLS)
_UNSAFE_TOOLS_ENV = "CODEJURY_CLAUDE_UNSAFE_TOOLS"

Runner = Callable[..., str]


def _drop_flag(args: tuple[str, ...], flag: str) -> tuple[str, ...]:
    """Drop `flag` and the value token following it from an arg tuple."""
    out: list[str] = []
    it = iter(args)
    for a in it:
        if a == flag:
            next(it, None)
            continue
        out.append(a)
    return tuple(out)


def _compose_claude_args(extra: tuple[str, ...], *, unsafe: bool) -> tuple[str, ...]:
    """The effective `claude -p` args. The read-only `--allowedTools` is mandatory: extra
    args from `CODEJURY_CLAUDE_ARGS` or the constructor are appended, but any
    `--allowedTools` they carry is dropped, so a misconfigured environment cannot silently
    turn a read-only review into a writing agent. `CODEJURY_CLAUDE_UNSAFE_TOOLS=1` is the
    one explicit way to hand tool selection to the extra args."""
    if unsafe:
        return (*_OUTPUT_ARGS, *extra)
    return (*_OUTPUT_ARGS, *READ_ONLY_TOOLS, *_drop_flag(extra, "--allowedTools"))


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
        input=prompt, cwd=cwd or None,
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


class _ClaudeBackend:
    def __init__(self, *, claude_bin: str | None = None, args: tuple[str, ...] | None = None,
                 timeout: int = 900, retries: int = 2, backoff: float = 10.0,
                 runner: Runner = _default_runner) -> None:
        self._bin = claude_bin or os.environ.get("CODEJURY_CLAUDE_BIN", "claude")
        env_args = os.environ.get("CODEJURY_CLAUDE_ARGS")
        extra = tuple(shlex.split(env_args)) if env_args else (tuple(args) if args else ())
        unsafe = os.environ.get(_UNSAFE_TOOLS_ENV) == "1"
        self._args = _compose_claude_args(extra, unsafe=unsafe)
        self._timeout = timeout
        self._retries = retries
        self._backoff = backoff
        self._runner = runner

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


class AgentReviewer(_ClaudeBackend, UnitReviewer):
    """Per-unit review as a headless Claude Code agent that reads the files itself."""

    def __init__(self, **kw) -> None:
        super().__init__(**kw)
        self._mandate = UNIT_REVIEW_FILE.read_text(encoding="utf-8")
        self._rubric = SEVERITY_RUBRIC_FILE.read_text(encoding="utf-8")

    def review(self, unit: Unit, lens: str, *, shared_context: str = "") -> list[Candidate]:
        files = "\n".join(f"- {f}" for f in unit.files)
        prompt = (
            f"{self._mandate}\n\n---\nSeverity rubric:\n{self._rubric}\n\n---\n{lens_line(lens)}"
            + (f"Stack and authorization model:\n{shared_context}\n\n" if shared_context else "")
            + f"Review unit `{unit.name}`. Read these files yourself and trace into the "
            f"managers, dao, controllers, and libraries they call:\n{files}\n\n"
            f"Respond with a single JSON object exactly like:\n{JSON_SHAPE}"
        )
        obj = require_json_object(
            _result_text(self._ask(prompt, unit.root)), required_key="findings", error=RepoReviewError,
            message="the unit review reply had no JSON object, or a JSON object without a "
                    "findings key, so it is a failed review rather than a clean unit",
        )
        return candidates_from_obj(obj)


_VERIFY_SHAPE = '{"real": true, "reason": "the controlling fact at file:line"}'


class AgentVerifier(_ClaudeBackend, Verifier):
    """Per-candidate refutation as a headless Claude Code agent that reads the code."""

    def __init__(self, **kw) -> None:
        super().__init__(**kw)
        self._traps = FALSE_POSITIVE_TRAPS_FILE.read_text(encoding="utf-8")

    def verify(self, candidate: Candidate, root: str) -> Verdict:
        prompt = (
            "Try to REFUTE this proposed finding. Read the cited code yourself and trace "
            "across files, then decide whether a controlling fact makes it genuinely safe, "
            "judging against PRODUCTION semantics, not a shallow read.\n\n"
            f"Traps to check against, in both directions, refuting a real finding as wrongly "
            f"as confirming a safe one:\n{self._traps}\n\n"
            "For a concurrency or lock claim you MUST read BOTH the locking query AND its "
            "caller, tracing across files, before judging whether the lock is taken on the "
            "contended row.\n\n"
            f"Proposed finding:\n- {candidate.title}\n- category: {candidate.category}\n"
            f"- endpoint: {candidate.endpoint}\n- location: {candidate.file}:{candidate.line}\n"
            f"- claimed evidence: {candidate.evidence}\n\n"
            "Read the code under the current directory, starting at the cited file, then "
            f"respond with a single JSON object exactly like:\n{_VERIFY_SHAPE}"
        )
        obj, ok = optional_json_object(_result_text(self._ask(prompt, root)), required_key="real")
        if not ok:
            return Verdict(real=True, reason="unparseable verification, kept")
        return Verdict(real=bool(obj.get("real")), reason=str(obj.get("reason", "")))
