"""Intra-procedural value-origin tracing (P1-01).

Classify where the value of an expression inside a function comes from, so a
later layer (P1-03) can decide whether it is attacker-controlled. The output is
an ``Origin``: the parameters, callees, attribute/subscript roots, free names,
and literals a value derives from.

The analysis is deliberately conservative and flow-insensitive: a name assigned
more than once contributes the union of all its right-hand sides, so a possible
source is never dropped (recall over precision). A value built only from literals
is reported as ``is_constant``, the signal that distinguishes, for example,
SQL concatenated from constants (safe) from SQL concatenated from a parameter.

This module finds where a value comes from; it does not decide what is a source
or a sanitizer (that is data, P1-02) nor follow a call into another file (P1-03).
Python / AST only.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class Origin:
    params: frozenset[str] = frozenset()    # parameters the value derives from
    calls: frozenset[str] = frozenset()     # callee names whose return it derives from
    attrs: frozenset[str] = frozenset()     # attribute/subscript roots, dotted (e.g. "request.args")
    globals_: frozenset[str] = frozenset()  # free names: module globals, imports, builtins
    has_literal: bool = False               # a literal contributes to the value
    unknown: bool = False                   # an unmodelled expression contributes (be cautious)

    def merge(self, other: Origin) -> Origin:
        return Origin(
            params=self.params | other.params,
            calls=self.calls | other.calls,
            attrs=self.attrs | other.attrs,
            globals_=self.globals_ | other.globals_,
            has_literal=self.has_literal or other.has_literal,
            unknown=self.unknown or other.unknown,
        )

    @property
    def is_constant(self) -> bool:
        """True when the value is built only from literals: no param, call, attr,
        free name, or unmodelled expression contributes."""
        return not (self.params or self.calls or self.attrs or self.globals_ or self.unknown)


_LITERAL = Origin(has_literal=True)
_UNKNOWN = Origin(unknown=True)


def parse_function(source: str, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Find the first function named ``name`` in ``source`` (any nesting)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def find_calls(scope: ast.AST, callee: str) -> list[ast.Call]:
    """Every call within ``scope`` whose function is named ``callee``, matching a
    bare name (``open``) or the final attribute (``execute`` in ``cur.execute``)."""
    return [node for node in ast.walk(scope) if isinstance(node, ast.Call) and _call_name(node) == callee]


def trace_value(func: ast.FunctionDef | ast.AsyncFunctionDef, expr: ast.AST) -> Origin:
    """Trace where ``expr`` (an expression inside ``func``) gets its value from."""
    params = _params(func)

    def leaf(node: ast.AST, recurse) -> Origin:
        if isinstance(node, ast.Call):
            # the return value's provenance depends on the callee's semantics, which
            # P1-03 decides with the vocabulary; here we just name the callee.
            name = _call_name(node)
            return Origin(calls=frozenset({name})) if name else _UNKNOWN
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            dotted = _dotted(node)
            origin = Origin(attrs=frozenset({dotted})) if dotted else _UNKNOWN
            if _root_name(node) in params:  # e.g. request.args[...] where `request` is a parameter
                origin = origin.merge(Origin(params=frozenset({_root_name(node)})))
            return origin
        return _UNKNOWN

    return reduce_value(
        expr,
        params=params,
        assigns=_assignments(func),
        combine=_merge_origins,
        leaf=leaf,
        on_param=lambda n: Origin(params=frozenset({n})),
        on_global=lambda n: Origin(globals_=frozenset({n})),
        on_constant=lambda: _LITERAL,
        on_cycle=Origin,  # assignment cycle, no new information
    )


def _merge_origins(origins: list[Origin]) -> Origin:
    out = Origin()
    for o in origins:
        out = out.merge(o)
    return out


def parameters(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """The parameter names of ``func`` (positional, keyword, *args, **kwargs)."""
    return _params(func)


def assignments(func: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, list[ast.AST]]:
    """Map each assigned local name to the right-hand sides it is assigned (union)."""
    return _assignments(func)


def callee(call: ast.Call) -> tuple[str | None, str | None]:
    """The (dotted, bare) callee of a call: ("json.loads", "loads") or ("open", "open")."""
    return _dotted(call.func), _call_name(call)


def access_path(node: ast.AST) -> str | None:
    """Dotted access chain with subscripts collapsed: request.args["x"] -> request.args."""
    return _dotted(node)


def access_root(node: ast.AST) -> str | None:
    """Leftmost name of an attribute/subscript chain: request.args["x"] -> request."""
    return _root_name(node)


def reduce_value(
    expr: ast.AST,
    *,
    params: set[str],
    assigns: dict[str, list[ast.AST]],
    combine,
    leaf,
    on_param,
    on_global,
    on_constant,
    on_cycle,
    seen: frozenset[str] = frozenset(),
):
    """Walk a value expression, folding it to a single result of the caller's type.

    This is the structural recursion shared by provenance (P1-01) and taint
    classification (P1-03): the composite forms that pass a value through (binops,
    f-strings, conditionals, collections) and the local-name dispatch (parameter /
    assignment chain / assignment cycle / free global) are handled here once. The
    caller supplies the policy:

    - ``combine(list)`` -> fold component results (also defines the empty result);
    - ``on_constant() / on_param(name) / on_global(name) / on_cycle()`` -> leaf
      results for a literal, a parameter, a free name, and an assignment cycle;
    - ``leaf(node, recurse)`` -> everything else (calls, attribute/subscript
      access, unmodelled nodes); ``recurse`` re-enters the walk for sub-expressions
      (e.g. a taint propagator recursing into its arguments).
    """

    def recurse(e: ast.AST, _seen: frozenset[str] | None = None):
        return reduce_value(
            e, params=params, assigns=assigns, combine=combine, leaf=leaf,
            on_param=on_param, on_global=on_global, on_constant=on_constant,
            on_cycle=on_cycle, seen=seen if _seen is None else _seen,
        )

    if isinstance(expr, ast.Constant):
        return on_constant()
    if isinstance(expr, ast.JoinedStr):  # f-string: literal parts + interpolated exprs
        return combine([on_constant()] + [recurse(v.value) for v in expr.values if isinstance(v, ast.FormattedValue)])
    if isinstance(expr, ast.BinOp):
        return combine([recurse(expr.left), recurse(expr.right)])
    if isinstance(expr, ast.BoolOp):
        return combine([recurse(v) for v in expr.values])
    if isinstance(expr, ast.IfExp):  # one branch or the other; the test does not flow in
        return combine([recurse(expr.body), recurse(expr.orelse)])
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return combine([recurse(e) for e in expr.elts])
    if isinstance(expr, ast.Name):
        if expr.id in seen:  # assignment cycle, stop
            return on_cycle()
        if expr.id in params:
            return on_param(expr.id)
        if expr.id in assigns:
            return combine([recurse(r, seen | {expr.id}) for r in assigns[expr.id]])
        return on_global(expr.id)  # module global, import, or builtin
    return leaf(expr, recurse)


def _params(func: ast.AST) -> set[str]:
    a = getattr(func, "args", None)
    if a is None:  # a module-level scope has no parameters
        return set()
    names = {arg.arg for arg in (*a.posonlyargs, *a.args, *a.kwonlyargs)}
    if a.vararg:
        names.add(a.vararg.arg)
    if a.kwarg:
        names.add(a.kwarg.arg)
    return names


def _assignments(func: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, list[ast.AST]]:
    out: dict[str, list[ast.AST]] = {}
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                for name in _target_names(target):
                    out.setdefault(name, []).append(node.value)
        elif isinstance(node, ast.AnnAssign) and node.value is not None and isinstance(node.target, ast.Name):
            out.setdefault(node.target.id, []).append(node.value)
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            out.setdefault(node.target.id, []).append(node.value)
    return out


def _target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for elt in target.elts for name in _target_names(elt)]
    return []


def _call_name(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _dotted(node: ast.AST) -> str | None:
    """Dotted access chain, with subscripts collapsed: request.args["x"] -> request.args."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    if isinstance(node, ast.Subscript):
        return _dotted(node.value)
    return None


def _root_name(node: ast.AST) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None
