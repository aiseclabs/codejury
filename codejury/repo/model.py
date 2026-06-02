"""RepoModel (P6-01): a deterministic, AST-built map of a repository.

The first stage of a whole-repo audit. Before any model call, this records what
the repo is: its files and its entrypoints, the functions where external input
arrives (HTTP routes, CLI commands). Later stages review the API surface (P6-02)
and trace attack paths (P6-03) on top of it.

Entrypoint signatures live in data, ``data/entrypoints.yaml``, so a new framework
is added without touching this analyzer. Detection is pure AST, no model call, so
the model is deterministic and cacheable.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

import yaml

from codejury.resources import ENTRYPOINTS_FILE


@dataclass(frozen=True, kw_only=True)
class Entrypoint:
    file: str
    line: int
    function: str
    kind: str            # "http" or "cli"
    framework: str
    route: str = ""
    method: str = ""


@dataclass(frozen=True, kw_only=True)
class RepoModel:
    root: str
    files: tuple[str, ...]
    entrypoints: tuple[Entrypoint, ...]


@dataclass(frozen=True)
class _Signatures:
    decorators: tuple[dict, ...]
    calls: tuple[dict, ...]


def load_entrypoint_signatures(path: str | Path = ENTRYPOINTS_FILE) -> _Signatures:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return _Signatures(decorators=tuple(data.get("decorators", [])), calls=tuple(data.get("calls", [])))


_SKIP_DIRS = frozenset({".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache"})


def _read_python_files(root: Path) -> dict[str, str]:
    """{relative path: content} for .py files under root, skipping noise dirs and
    symlinks that escape the tree."""
    root = root.resolve()
    files: dict[str, str] = {}
    for path in root.rglob("*.py"):
        rel = path.relative_to(root)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        try:
            if not path.resolve().is_relative_to(root):
                continue  # symlink escaping the tree
            files[str(rel)] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError, ValueError):
            continue
    return files


def build_repo_model_from_dir(root: str | Path, *, signatures: _Signatures | None = None) -> RepoModel:
    """Build a RepoModel by reading the .py files under a directory."""
    return build_repo_model(root, _read_python_files(Path(root)), signatures=signatures)


def build_repo_model(root: str | Path, files: dict[str, str], *, signatures: _Signatures | None = None) -> RepoModel:
    """Build a RepoModel from {path: content}. Files that do not parse are skipped."""
    sigs = signatures or load_entrypoint_signatures()
    asts: dict[str, ast.Module] = {}
    for path, content in sorted(files.items()):
        try:
            asts[path] = ast.parse(content)
        except SyntaxError:
            continue  # unparseable file is skipped, not fatal
    entrypoints: list[Entrypoint] = []
    for path, tree in asts.items():
        entrypoints.extend(_decorator_entrypoints_in(path, tree, sigs.decorators))
    # route-call entrypoints (Django path()): resolved across files so an
    # include() mount contributes its sub-routes under the mount's prefix
    entrypoints.extend(_route_call_entrypoints(asts, sigs.calls))
    # an entrypoint must name a reviewable handler function; drop entries with no
    # resolvable function (an unresolved view) so the seeded inventory stays clean
    entrypoints = [e for e in entrypoints if e.function]
    return RepoModel(root=str(root), files=tuple(sorted(files)), entrypoints=tuple(entrypoints))


def _decorator_entrypoints_in(path: str, tree: ast.Module, deco_sigs) -> list[Entrypoint]:
    out: list[Entrypoint] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                ep = _decorator_entrypoint(path, node, dec, deco_sigs)
                if ep is not None:
                    out.append(ep)
    return out


def _decorator_name(dec: ast.AST) -> str | None:
    func = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _decorator_entrypoint(path, func, dec, deco_sigs) -> Entrypoint | None:
    name = _decorator_name(dec)
    if name is None:
        return None
    sig = next((s for s in deco_sigs if name in s["names"]), None)
    if sig is None:
        return None
    call = dec if isinstance(dec, ast.Call) else None
    return Entrypoint(
        file=path,
        line=func.lineno,
        function=func.name,
        kind=sig["kind"],
        framework=sig["framework"],
        route=_first_str_arg(call) if call else "",
        method=_method(name, call, sig.get("method", "")),
    )


# names of the call that mounts a sub-urlconf (Django include()); a route call
# whose view position is one of these recurses into the included module
_INCLUDE_NAMES = frozenset({"include"})


def _call_name(call: ast.Call) -> str | None:
    f = call.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return None


def _route_calls(tree: ast.Module, names: set[str]) -> list[ast.Call]:
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call) and _call_name(n) in names]


def _include_module(call: ast.Call) -> str | None:
    """If this route call mounts a sub-urlconf via include('a.b.urls'), return the
    dotted module; else None. Handles include('mod') and include(('mod', 'ns'))."""
    if len(call.args) < 2 or not isinstance(call.args[1], ast.Call):
        return None
    inc = call.args[1]
    if _call_name(inc) not in _INCLUDE_NAMES or not inc.args:
        return None
    a = inc.args[0]
    if isinstance(a, ast.Constant) and isinstance(a.value, str):
        return a.value
    if isinstance(a, ast.Tuple) and a.elts and isinstance(a.elts[0], ast.Constant) and isinstance(a.elts[0].value, str):
        return a.elts[0].value
    return None


def _module_to_file(module: str, files: set[str]) -> str | None:
    """Resolve a dotted module ('app.urls') to a file in the repo, by exact path or
    a suffix match (the dotted path may be rooted above the scanned tree)."""
    candidate = module.replace(".", "/") + ".py"
    if candidate in files:
        return candidate
    matches = sorted(f for f in files if f.endswith("/" + candidate))
    return matches[0] if matches else None


def _route_call_entrypoints(asts: dict[str, ast.Module], call_sigs) -> list[Entrypoint]:
    if not call_sigs:
        return []
    names = {n for s in call_sigs for n in s["names"]}
    sig_by_name = {n: s for s in call_sigs for n in s["names"]}
    files = set(asts)

    # files mounted by another file's include() are not roots; they are emitted
    # only through the include chain, with the mount prefix, never standalone
    mounted: set[str] = set()
    for tree in asts.values():
        for call in _route_calls(tree, names):
            mod = _include_module(call)
            target = _module_to_file(mod, files) if mod else None
            if target:
                mounted.add(target)

    out: list[Entrypoint] = []
    for path in sorted(asts):
        if path not in mounted:
            _emit_routes(path, "", asts, files, names, sig_by_name, {path}, out)
    return out


def _emit_routes(path, prefix, asts, files, names, sig_by_name, visited, out) -> None:
    for call in _route_calls(asts[path], names):
        seg = _first_str_arg(call)
        mod = _include_module(call)
        if mod:
            target = _module_to_file(mod, files)
            if target and target not in visited:
                _emit_routes(target, prefix + seg, asts, files, names, sig_by_name, visited | {target}, out)
            continue
        view = _view_name(call)
        if not view:
            continue
        sig = sig_by_name[_call_name(call)]
        out.append(Entrypoint(
            file=path, line=call.lineno, function=view,
            kind=sig["kind"], framework=sig["framework"], route=prefix + seg,
        ))


def _first_str_arg(call: ast.Call) -> str:
    if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
        return call.args[0].value
    return ""


def _method(decorator_name: str, call: ast.Call | None, rule: str) -> str:
    if rule == "name":
        return decorator_name.upper()
    if rule == "kwarg:methods" and call is not None:
        for kw in call.keywords:
            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                methods = [e.value for e in kw.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
                if methods:
                    return ",".join(methods)
        return "GET"  # the framework default when methods is omitted
    return ""


def _view_name(call: ast.Call) -> str:
    # Django path("route", view): the view is the second positional argument
    if len(call.args) >= 2:
        view = call.args[1]
        if isinstance(view, ast.Name):
            return view.id
        if isinstance(view, ast.Attribute):
            return view.attr
    return ""
