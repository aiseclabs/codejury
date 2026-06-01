"""Taint classification (P1-03): turn provenance into a taint verdict.

Walks a value expression like P1-01's tracer, but consults the taint vocabulary
(P1-02) at every call and access: a known source makes a value EXTERNAL, a known
sanitizer makes it SANITIZED (taint stops), a propagator carries taint through to
the result, and a trusted origin or a literal is clean.

The point is to let a later layer (P1-04) downgrade a taint finding only when the
value is *provably* not attacker-controlled -- ``classification in SAFE`` -- so
recall is preserved: anything uncertain is UNKNOWN or PARAM, never quietly safe.

Two documented precision leans: a bare module-global name (e.g. ``STATIC_DIR``)
is treated as TRUSTED (module-level names are conventionally constants), and an
unknown attribute access (e.g. ``self.x``) is UNKNOWN rather than safe. These are
revisited against real repositories in P1-05.

This layer is intra-procedural: a value that depends on a parameter returns
PARAM, for the cross-file caller hop (next) to resolve.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import yaml

from codejury.analysis.provenance import (
    access_path,
    access_root,
    assignments,
    callee,
    parameters,
)
from codejury.resources import TAINT_FILE


class Taint(str, Enum):
    EXTERNAL = "external"    # derives from an attacker source, not sanitized
    UNKNOWN = "unknown"      # an unknown call / access -- cannot prove either way
    PARAM = "param"          # depends on a parameter; resolve at the call site (cross-file)
    SANITIZED = "sanitized"  # had an external component, but a sanitizer neutralized it
    TRUSTED = "trusted"      # operator/config/global origin
    CONSTANT = "constant"    # built only from literals


# Provably-not-attacker-controlled: the only classes P1-04 may downgrade on.
SAFE = frozenset({Taint.CONSTANT, Taint.SANITIZED, Taint.TRUSTED})

# Ranked for combining a composite value: the most dangerous component wins.
_RANK = {
    Taint.EXTERNAL: 6,
    Taint.UNKNOWN: 5,
    Taint.PARAM: 4,
    Taint.SANITIZED: 3,
    Taint.TRUSTED: 2,
    Taint.CONSTANT: 1,
}


@dataclass(frozen=True)
class TaintVocab:
    sources: tuple[str, ...]
    trusted: tuple[str, ...]
    sanitizers: tuple[str, ...]
    safe_sinks: tuple[str, ...]
    propagators: tuple[str, ...]

    @classmethod
    def from_dict(cls, data: dict) -> TaintVocab:
        def match(section: str) -> tuple[str, ...]:
            return tuple(m for e in data.get(section, []) for m in e.get("match", []))

        def calls(section: str) -> tuple[str, ...]:
            return tuple(c for e in data.get(section, []) for c in e.get("calls", []))

        return cls(
            sources=match("sources"),
            trusted=match("trusted"),
            sanitizers=calls("sanitizers"),
            safe_sinks=calls("safe_sinks"),
            propagators=calls("propagators"),
        )


def load_vocab(path: str | Path = TAINT_FILE) -> TaintVocab:
    with open(path, encoding="utf-8") as f:
        return TaintVocab.from_dict(yaml.safe_load(f) or {})


def is_safe_sink(call: ast.Call, vocab: TaintVocab) -> bool:
    """True if the call itself is a safe parser (json.loads, ast.literal_eval, ...)."""
    return _callee_in(call, vocab.safe_sinks)


def taint_of(func: ast.FunctionDef | ast.AsyncFunctionDef, expr: ast.AST, vocab: TaintVocab) -> Taint:
    """Classify the taint of ``expr`` within ``func`` using the vocabulary."""
    return _walk(func, expr, vocab, assignments(func), parameters(func), frozenset())


def _walk(func, expr, vocab, assigns, params, seen) -> Taint:
    if isinstance(expr, ast.Constant):
        return Taint.CONSTANT
    if isinstance(expr, ast.JoinedStr):
        parts = [Taint.CONSTANT]
        parts += [_walk(func, v.value, vocab, assigns, params, seen)
                  for v in expr.values if isinstance(v, ast.FormattedValue)]
        return _combine(parts)
    if isinstance(expr, ast.BinOp):
        return _combine([_walk(func, expr.left, vocab, assigns, params, seen),
                         _walk(func, expr.right, vocab, assigns, params, seen)])
    if isinstance(expr, ast.BoolOp):
        return _combine([_walk(func, v, vocab, assigns, params, seen) for v in expr.values])
    if isinstance(expr, ast.IfExp):
        return _combine([_walk(func, expr.body, vocab, assigns, params, seen),
                         _walk(func, expr.orelse, vocab, assigns, params, seen)])
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return _combine([_walk(func, e, vocab, assigns, params, seen) for e in expr.elts] or [Taint.CONSTANT])
    if isinstance(expr, ast.Call):
        if _callee_in(expr, vocab.sanitizers):
            return Taint.SANITIZED            # a sanitizer cleans its result regardless of input
        if _callee_in(expr, vocab.sources):
            return Taint.EXTERNAL             # e.g. input()
        if _callee_in(expr, vocab.propagators) or _callee_in(expr, vocab.safe_sinks):
            return _combine([_walk(func, a, vocab, assigns, params, seen) for a in expr.args] or [Taint.CONSTANT])
        return Taint.UNKNOWN                  # unknown call -- a cross-file hop may resolve it later
    if isinstance(expr, (ast.Attribute, ast.Subscript)):
        path = access_path(expr)
        if path and _access_in(path, vocab.sources):
            return Taint.EXTERNAL
        if path and _access_in(path, vocab.trusted):
            return Taint.TRUSTED
        if access_root(expr) in params:
            return Taint.PARAM                # attribute of a parameter -- resolve at call site
        return Taint.UNKNOWN                  # unknown object attribute (e.g. self.x): not provably safe
    if isinstance(expr, ast.Name):
        if expr.id in seen:
            return Taint.CONSTANT             # assignment cycle: no new information
        if expr.id in params:
            return Taint.PARAM
        if expr.id in assigns:
            return _combine([_walk(func, r, vocab, assigns, params, seen | {expr.id}) for r in assigns[expr.id]])
        return Taint.TRUSTED                  # free module global / builtin -- conventionally a constant
    return Taint.UNKNOWN


def _combine(taints: list[Taint]) -> Taint:
    return max(taints, key=lambda t: _RANK[t])


def _callee_in(call: ast.Call, names: tuple[str, ...]) -> bool:
    dotted, bare = callee(call)
    for name in names:
        if "." in name:
            if dotted is not None and (dotted == name or dotted.endswith("." + name)):
                return True
        elif bare == name:
            return True
    return False


def _access_in(path: str, prefixes: tuple[str, ...]) -> bool:
    # "request.args" matches the source "request.args" and also "request.args.get"
    return any(path == p or path.startswith(p + ".") for p in prefixes)
