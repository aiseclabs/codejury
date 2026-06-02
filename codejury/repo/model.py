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
    entrypoints: list[Entrypoint] = []
    for path, content in sorted(files.items()):
        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue
        entrypoints.extend(_entrypoints_in(path, tree, sigs))
    return RepoModel(root=str(root), files=tuple(sorted(files)), entrypoints=tuple(entrypoints))


def _entrypoints_in(path: str, tree: ast.Module, sigs: _Signatures) -> list[Entrypoint]:
    out: list[Entrypoint] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                ep = _decorator_entrypoint(path, node, dec, sigs.decorators)
                if ep is not None:
                    out.append(ep)
        elif isinstance(node, ast.Call):
            ep = _call_entrypoint(path, node, sigs.calls)
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


def _call_entrypoint(path, call, call_sigs) -> Entrypoint | None:
    name = call.func.attr if isinstance(call.func, ast.Attribute) else (
        call.func.id if isinstance(call.func, ast.Name) else None
    )
    sig = next((s for s in call_sigs if name in s["names"]), None)
    if sig is None:
        return None
    return Entrypoint(
        file=path,
        line=call.lineno,
        function=_view_name(call),
        kind=sig["kind"],
        framework=sig["framework"],
        route=_first_str_arg(call),
    )


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
