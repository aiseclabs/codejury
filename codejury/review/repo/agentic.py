"""Agentic per-unit reviewer: audit a unit like a human, following calls into the code they
invoke with the navigation tools before judging, instead of reading one fixed text bundle.

A single grounded call sees only the code packed into its prompt, so a cross-file or inherited
defect is invisible to it. This reviewer is given read_file, grep, and find_definition, and
drives them in a loop: it asks for a tool, gets the result, follows the call deeper, and only
then reports. The loop is a text protocol over the plain `complete()` interface, one JSON
object per turn, so it drives any provider, Claude or a gpt-5 model, with no per-provider
tool-use plumbing, and it plugs into the same `UnitReviewer` seam as the single-call reviewer,
so the pass-loop, the multi-model fan-out, and the cross-confirmation all reuse it unchanged.

The step budget bounds cost, and a run that exhausts it without findings is a failed review,
counted not read as a clean unit, invariant 3. Tool reads are scoped to the repo by the
navigation layer, so the reviewer cannot fetch a file outside the target.
"""

from __future__ import annotations

from codejury.domains.base import ContentPaths
from codejury.json_parse import extract_json_object
from codejury.providers.base import Message, Provider
from codejury.resources import SEVERITY_RUBRIC_FILE, UNIT_REVIEW_FILE
from codejury.review.repo import navigation
from codejury.review.repo.reviewer import (
    RepoReviewError,
    Unit,
    UnitReviewer,
    _gather,
    candidates_from_obj,
)
from codejury.review.repo.shapes import JSON_SHAPE, lens_line
from codejury.review.repo.union import Candidate

_SYSTEM = (
    "You are a senior application security engineer auditing one slice of a codebase like a "
    "human: when the code calls a function, a method, or an inherited or imported implementation "
    "whose behavior decides whether a finding is real, FOLLOW it with the tools and read it "
    "before you judge, do not assume. Report only real, evidenced, exploitable findings, each at "
    "a concrete file:line."
)

_PROTOCOL = (
    "Work in turns. Each turn reply with ONE JSON object and nothing else, either a tool call "
    "or your final findings.\n"
    'Tool call: {"tool": "read_file", "args": {"path": "rel/path.ext", "start": 1, "end": 80}} '
    'or {"tool": "grep", "args": {"pattern": "regex"}} '
    'or {"tool": "find_definition", "args": {"symbol": "name"}}.\n'
    "Use find_definition to follow a call into the implementation it invokes, including an "
    "inherited base or a called library on the path, then read_file to confirm. Paths are "
    "relative to the repo root.\n"
    f"When you have followed enough to judge, reply with your findings exactly like:\n{JSON_SHAPE}\n"
    'If nothing is exploitable, reply {"findings": []}.'
)


def _fmt_hits(hits: list[dict]) -> str:
    if not hits:
        return "[no matches]"
    return "\n".join(f"{h['file']}:{h['line']}: {h['text']}" for h in hits)


class AgenticReviewer(UnitReviewer):
    """A reviewer that follows calls with tools before judging, driven over `complete()`."""

    def __init__(self, *, provider: Provider, model: str, max_tokens: int = 4096,
                 max_steps: int = 12, content: ContentPaths | None = None) -> None:
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens
        self._max_steps = max(1, max_steps)
        mandate_file = content.unit_review_file if content else UNIT_REVIEW_FILE
        rubric_file = content.severity_rubric_file if content else SEVERITY_RUBRIC_FILE
        self._mandate = mandate_file.read_text(encoding="utf-8")
        self._rubric = rubric_file.read_text(encoding="utf-8")

    @property
    def label(self) -> str:
        return self._model

    def _dispatch(self, tool: str, args: dict, root: str) -> str:
        if tool == "read_file":
            return navigation.read_file(root, str(args.get("path", "")), args.get("start"), args.get("end"))
        if tool == "grep":
            return _fmt_hits(navigation.grep(root, str(args.get("pattern", ""))))
        if tool == "find_definition":
            return _fmt_hits(navigation.find_definition(root, str(args.get("symbol", ""))))
        return f"[unknown tool: {tool}]"

    def _ask(self, messages: list[Message]) -> str:
        return self._provider.complete(
            system=_SYSTEM, messages=messages, model=self._model,
            max_tokens=self._max_tokens, cache=True,
        ).text

    def review(self, unit: Unit, lens: str, *, shared_context: str = "") -> list[Candidate]:
        prompt = (
            f"{self._mandate}\n\n---\nSeverity rubric:\n{self._rubric}\n\n---\n"
            f"{lens_line(lens)}"
            + (f"Stack and authorization model:\n{shared_context}\n\n" if shared_context else "")
            + f"Unit `{unit.name}`, the code to start from:\n```\n{_gather(unit)}\n```\n\n"
            f"{_PROTOCOL}"
        )
        messages = [Message(role="user", content=prompt)]
        nudge = 'Reply with ONE JSON object: a tool call, or {"findings": [...]}.'
        for _ in range(self._max_steps):
            text = self._ask(messages)
            obj = extract_json_object(text)
            if obj is not None and "findings" in obj:
                return candidates_from_obj(obj)
            messages.append(Message(role="assistant", content=text))
            if obj is not None and obj.get("tool"):
                out = self._dispatch(str(obj["tool"]), obj.get("args") or {}, unit.root)
                messages.append(Message(role="user", content=f"TOOL RESULT ({obj['tool']}):\n{out}"))
            else:
                messages.append(Message(role="user", content=nudge))
        # budget spent: one last call demanding findings, then fail loud if still unusable
        messages.append(Message(role="user", content=(
            "Step budget reached. Reply now with your findings as a single JSON object "
            '{"findings": [...]}, empty if none.')))
        obj = extract_json_object(self._ask(messages))
        if obj is None or "findings" not in obj:
            raise RepoReviewError(
                "agentic review produced no findings object within the step budget, a failed "
                "review counted not read as a clean unit")
        return candidates_from_obj(obj)
