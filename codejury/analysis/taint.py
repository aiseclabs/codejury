"""Taint classification (P1-03): turn provenance into a taint verdict.

Walks a value expression like P1-01's tracer, but consults the taint vocabulary
(P1-02) at every call and access: a known source makes a value EXTERNAL, a known
sanitizer makes it SANITIZED (taint stops), a propagator carries taint through to
the result, and a trusted origin or a literal is clean.

The point is to let a later layer (P1-04) downgrade a taint finding only when the
value is *provably* not attacker-controlled (``classification in SAFE``), so
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
import functools
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import yaml

from codejury.analysis.provenance import (
    access_path,
    access_root,
    assignments,
    callee,
    find_calls,
    parameters,
    reduce_value,
)
from codejury.resources import TAINT_FILE


class Taint(str, Enum):
    EXTERNAL = "external"    # derives from an attacker source, not sanitized
    UNKNOWN = "unknown"      # an unknown call / access; cannot prove either way
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


def taint_of(
    func: ast.AST,
    expr: ast.AST,
    vocab: TaintVocab,
    *,
    resolve_param=None,
) -> Taint:
    """Classify the taint of ``expr`` within ``func`` using the vocabulary.

    ``resolve_param`` is an optional ``(name) -> Taint`` callback; when given, a
    value that reaches a parameter is resolved through it (the cross-file caller
    hop, P1-03b) instead of returning PARAM. Shares the structural recursion with
    provenance via ``reduce_value``; this is the vocabulary-aware policy.
    """
    params = parameters(func)

    def on_param(name: str) -> Taint:
        return resolve_param(name) if resolve_param else Taint.PARAM

    def leaf(node: ast.AST, recurse) -> Taint:
        if isinstance(node, ast.Call):
            if _callee_in(node, vocab.sanitizers):
                return Taint.SANITIZED        # a sanitizer cleans its result regardless of input
            if _callee_in(node, vocab.sources):
                return Taint.EXTERNAL         # e.g. input()
            # a method ON a source/trusted object, e.g. request.args.get("id")
            func_path = access_path(node.func)
            if func_path and _access_in(func_path, vocab.sources):
                return Taint.EXTERNAL
            if func_path and _access_in(func_path, vocab.trusted):
                return Taint.TRUSTED
            if _callee_in(node, vocab.propagators) or _callee_in(node, vocab.safe_sinks):
                return _combine([recurse(a) for a in node.args])
            return Taint.UNKNOWN              # unknown call; a cross-file hop may resolve it later
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            path = access_path(node)
            if path and _access_in(path, vocab.sources):
                return Taint.EXTERNAL
            if path and _access_in(path, vocab.trusted):
                return Taint.TRUSTED
            if access_root(node) in params:   # attribute of a parameter; resolve at the call site
                return on_param(access_root(node))
            return Taint.UNKNOWN              # unknown object attribute (e.g. self.x): not provably safe
        return Taint.UNKNOWN

    return reduce_value(
        expr,
        params=params,
        assigns=assignments(func),
        combine=_combine,
        leaf=leaf,
        on_param=on_param,
        on_global=lambda n: Taint.TRUSTED,    # free module global / builtin; conventionally a constant
        on_constant=lambda: Taint.CONSTANT,
        on_cycle=lambda: Taint.CONSTANT,      # assignment cycle: no new information
    )


def _combine(taints: list[Taint]) -> Taint:
    return max(taints, key=lambda t: _RANK[t]) if taints else Taint.CONSTANT


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


# --- cross-file one-hop resolution (P1-03b) ---------------------------------

def taint_in_repo(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    expr: ast.AST,
    vocab: TaintVocab,
    files: dict[str, str],
) -> Taint:
    """Classify ``expr`` in ``func``, resolving a value that reaches a parameter by
    looking one hop up at how ``func`` is called across ``files``.

    Combines all call sites: if any caller passes an attacker-controlled value the
    result is EXTERNAL; if every caller passes a sanitized/constant/trusted value it
    is safe. With no caller found, the parameter stays UNKNOWN (not assumed safe).
    """
    return taint_of(func, expr, vocab, resolve_param=_caller_resolver(func, files, vocab))


def _caller_resolver(func, files, vocab):
    sites = _call_sites(func.name, files)  # computed once, reused across parameters
    def resolve(param_name: str) -> Taint:
        index = _param_index(func, param_name)
        results = []
        for scope, call in sites:
            arg = _arg_for_param(call, index, param_name)
            # one hop only: classify the caller's argument without recursing further
            results.append(taint_of(scope, arg, vocab) if arg is not None else Taint.UNKNOWN)
        return _combine(results) if results else Taint.UNKNOWN
    return resolve


def _param_index(func, name: str) -> int | None:
    positional = [*func.args.posonlyargs, *func.args.args]
    if positional and positional[0].arg in ("self", "cls"):
        positional = positional[1:]  # bound-method call sites omit the receiver
    for i, arg in enumerate(positional):
        if arg.arg == name:
            return i
    return None  # keyword-only or *args: matched by keyword at the call site instead


def _arg_for_param(call: ast.Call, index: int | None, name: str) -> ast.AST | None:
    if index is not None and index < len(call.args):
        return call.args[index]
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


@functools.lru_cache(maxsize=256)
def _parse(source: str) -> ast.Module | None:
    """Parse a source string once and cache it (the same files are walked repeatedly
    during cross-file resolution); None if it does not parse."""
    try:
        return ast.parse(source)
    except SyntaxError:
        return None


def _call_sites(name: str, files: dict[str, str]) -> list[tuple[ast.AST, ast.Call]]:
    sites = []
    for source in files.values():
        tree = _parse(source)
        if tree is None:
            continue
        funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for call in find_calls(tree, name):
            sites.append((_enclosing_scope(funcs, call) or tree, call))
    return sites


def _enclosing_scope(funcs: list[ast.AST], call: ast.Call) -> ast.AST | None:
    containing = [f for f in funcs if any(node is call for node in ast.walk(f))]
    if not containing:
        return None  # module-level call site
    return min(containing, key=lambda f: sum(1 for _ in ast.walk(f)))  # innermost


def worst_sink_taint(content: str, files: dict[str, str], vocab: TaintVocab) -> Taint | None:
    """The most dangerous taint reaching any potential sink call in ``content``.

    A "potential sink" is any call that is not a safe sink, sanitizer, or
    propagator (those are not where injection happens). Each such call's argument
    taint is classified with the cross-file resolver. A safe sink that consumes
    tainted data (e.g. ``json.loads(request.data)``) contributes SANITIZED: the
    data was handled safely. The worst contribution is returned.

    ``Taint.UNKNOWN`` when no inspectable sink is found (the artifact may still be
    unsafe via a return value or an implicit sink, so it is NOT assumed clean);
    ``None`` when the code does not parse. The taint gate downgrades a finding only
    on a SAFE result, so an unproven artifact keeps its findings (recall preserved).
    """
    tree = _parse(content)
    if tree is None:
        return None
    funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    taints: list[Taint] = []
    for call in [n for n in ast.walk(tree) if isinstance(n, ast.Call)]:
        if is_safe_sink(call, vocab):
            taints.append(Taint.SANITIZED)  # tainted data consumed by a safe parser
            continue
        if _callee_in(call, vocab.sanitizers) or _callee_in(call, vocab.propagators):
            continue  # not a sink itself; counted via the enclosing sink's argument
        scope = _enclosing_scope(funcs, call) or tree
        for arg in (*call.args, *(kw.value for kw in call.keywords)):
            taints.append(taint_in_repo(scope, arg, vocab, files))
    return _combine(taints) if taints else Taint.UNKNOWN
