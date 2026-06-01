"""Intra-procedural value-origin tracing (P1-01).

Classify where the value of an expression inside a function comes from, so a
later layer (P1-03) can decide whether it is attacker-controlled. The output is
an ``Origin``: the parameters, callees, attribute/subscript roots, free names,
and literals a value derives from.

The analysis is deliberately conservative and flow-insensitive: a name assigned
more than once contributes the union of all its right-hand sides, so a possible
source is never dropped (recall over precision). A value built only from literals
is reported as ``is_constant`` -- the signal that distinguishes, for example,
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
        """True when the value is built only from literals -- no param, call, attr,
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
    """Every call within ``scope`` whose function is named ``callee`` -- matching a
    bare name (``open``) or the final attribute (``execute`` in ``cur.execute``)."""
    return [node for node in ast.walk(scope) if isinstance(node, ast.Call) and _call_name(node) == callee]


def trace_value(func: ast.FunctionDef | ast.AsyncFunctionDef, expr: ast.AST) -> Origin:
    """Trace where ``expr`` (an expression inside ``func``) gets its value from."""
    return _classify(expr, _params(func), _assignments(func), frozenset())


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


def _classify(expr: ast.AST, params: set[str], assigns: dict[str, list[ast.AST]], seen: frozenset[str]) -> Origin:
    if isinstance(expr, ast.Constant):
        return _LITERAL
    if isinstance(expr, ast.JoinedStr):  # f-string: literal parts + interpolated exprs
        origin = _LITERAL
        for value in expr.values:
            if isinstance(value, ast.FormattedValue):
                origin = origin.merge(_classify(value.value, params, assigns, seen))
        return origin
    if isinstance(expr, ast.BinOp):
        return _classify(expr.left, params, assigns, seen).merge(_classify(expr.right, params, assigns, seen))
    if isinstance(expr, (ast.BoolOp,)):
        return _merge_all(expr.values, params, assigns, seen)
    if isinstance(expr, ast.IfExp):  # value is one branch or the other; the test does not flow in
        return _classify(expr.body, params, assigns, seen).merge(_classify(expr.orelse, params, assigns, seen))
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return _merge_all(expr.elts, params, assigns, seen)
    if isinstance(expr, ast.Call):
        # the return value's taint depends on the callee's semantics, which P1-03
        # decides with the sanitizer/propagator catalog; here we just name the callee.
        name = _call_name(expr)
        return Origin(calls=frozenset({name})) if name else _UNKNOWN
    if isinstance(expr, (ast.Attribute, ast.Subscript)):
        dotted = _dotted(expr)
        origin = Origin(attrs=frozenset({dotted})) if dotted else _UNKNOWN
        root = _root_name(expr)
        if root in params:  # e.g. request.args[...] where `request` is a parameter
            origin = origin.merge(Origin(params=frozenset({root})))
        return origin
    if isinstance(expr, ast.Name):
        if expr.id in seen:  # assignment cycle -- stop
            return Origin()
        if expr.id in params:
            return Origin(params=frozenset({expr.id}))
        if expr.id in assigns:
            return _merge_all(assigns[expr.id], params, assigns, seen | {expr.id})
        return Origin(globals_=frozenset({expr.id}))  # module global, import, or builtin
    return _UNKNOWN


def _merge_all(exprs: list[ast.AST], params, assigns, seen) -> Origin:
    origin = Origin()
    for e in exprs:
        origin = origin.merge(_classify(e, params, assigns, seen))
    return origin


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
