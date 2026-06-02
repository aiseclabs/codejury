"""Suspected attack-path synthesis (P6-03).

Turns a flagged problem into a source -> sink path, anchoring each hop to a real
code location: the external-input expression (source) and the dangerous operation
the finding already cites (sink). When the source is in the cross-file caller
(``artifact.context``), the path crosses files.

These paths are **suspected**, not proven: they are stitched from the taint
vocabulary and the finding's evidence, not from a full data-flow graph, so they
carry ``attack_path_proven=False``. A path is only ever emitted when a real
external-input anchor exists; nothing is narrated without a code location (P6-05
upgrades suspected to proven via the deeper graph).
"""

from __future__ import annotations

import ast
import dataclasses

from codejury.analysis.provenance import access_path
from codejury.analysis.taint import TaintVocab, load_vocab
from codejury.domain.artifact import CodeArtifact
from codejury.domain.observation import PathStep, is_problem
from codejury.domain.result import AnalysisResult

_CONTEXT_FILE = "<context>"


def _matches(path: str, sources: tuple[str, ...]) -> bool:
    return any(path == s or path.startswith(s + ".") for s in sources)


def _find_source(code: str, sources: tuple[str, ...]) -> tuple[int, str] | None:
    """The earliest external-input expression in ``code`` as (line, access path)."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None
    best: tuple[int, str] | None = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            path = access_path(node)
        elif isinstance(node, ast.Call):
            path = access_path(node.func)
        else:
            continue
        line = getattr(node, "lineno", None)
        if path and line and _matches(path, sources):
            if best is None or line < best[0]:
                best = (line, path)
    return best


def suspected_path(
    *,
    content: str,
    context: str = "",
    sink_file: str,
    sink_line: int | None,
    sink_note: str = "",
    vocab: TaintVocab | None = None,
) -> list[PathStep]:
    """A suspected source -> sink path, or [] when no real source/sink anchor exists.

    The source is the first external-input expression in the code under review,
    or, failing that, in the cross-file caller context. The sink is the cited
    location. Every returned step has a real line."""
    if sink_line is None:
        return []
    vocab = vocab or load_vocab()
    local = _find_source(content, vocab.sources)
    if local:
        source = PathStep(file=sink_file, line=local[0], role="source", note=local[1])
    else:
        upstream = _find_source(context, vocab.sources) if context else None
        if not upstream:
            return []  # no external-input anchor: do not fabricate a path
        source = PathStep(file=_CONTEXT_FILE, line=upstream[0], role="source", note=upstream[1])
    return [source, PathStep(file=sink_file, line=sink_line, role="sink", note=sink_note)]


def attach_suspected_paths(
    result: AnalysisResult, artifact: CodeArtifact, *, vocab: TaintVocab | None = None
) -> AnalysisResult:
    """Add a suspected attack path to each flagged problem that cites a location
    and does not already carry one. Returns the result unchanged when nothing
    applies, so it is cheap to call on every run."""
    if result.error:
        return result
    vocab = vocab or load_vocab()
    enriched = []
    changed = False
    for o in result.observations:
        evidence = getattr(o, "evidence", None)
        if is_problem(o) and evidence and not getattr(o, "attack_path", None):
            sink = next((e for e in evidence if e.line is not None), None)
            if sink is not None:
                steps = suspected_path(
                    content=artifact.content,
                    context=artifact.context,
                    sink_file=sink.file or artifact.path,
                    sink_line=sink.line,
                    sink_note=o.capability,
                    vocab=vocab,
                )
                if steps:
                    o = dataclasses.replace(o, attack_path=steps, attack_path_proven=False)
                    changed = True
        enriched.append(o)
    return AnalysisResult(observations=enriched, error=result.error) if changed else result
