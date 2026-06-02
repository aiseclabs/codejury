"""ApiSurfaceSource (P6-02): one artifact per HTTP handler, plus the whole
endpoint inventory as context.

Turns a repository into the units the ``api_design`` capability reviews. Each
artifact is one route handler's source; its context is the full list of
endpoints (method, route, handler, decorators) so the model can judge
cross-endpoint architecture, e.g. one mutating route missing the auth decorator
its siblings carry, rather than a single-file vulnerability.

The endpoint set comes from the deterministic RepoModel (P6-01); only the
verdict is left to the model.
"""

from __future__ import annotations

import ast
from pathlib import Path

from codejury.analysis.repo_model import Entrypoint, build_repo_model
from codejury.domain.artifact import CodeArtifact
from codejury.sources.base import Source


class ApiSurfaceSource(Source):
    def __init__(self, files: dict[str, str], *, root: str | Path = ".") -> None:
        self._files = files
        self._root = str(root)

    @classmethod
    def from_dir(cls, root: str | Path) -> ApiSurfaceSource:
        from codejury.sources.repo import RepoSource

        files = RepoSource(root, extensions=(".py",)).read_files()
        return cls(files, root=root)

    def list_artifacts(self) -> list[CodeArtifact]:
        model = build_repo_model(self._root, self._files)
        http = [e for e in model.entrypoints if e.kind == "http"]
        if not http:
            return []

        handlers = _handler_index(self._files)  # (file, function) -> (source, decorators)
        inventory = _inventory(http, handlers)

        artifacts: list[CodeArtifact] = []
        seen: set[tuple[str, str]] = set()
        for ep in http:
            key = (ep.file, ep.function)
            if key in seen:
                continue  # one artifact per handler even when it serves several routes
            seen.add(key)
            handler = handlers.get(key)
            if handler is None:
                continue  # route registered but the handler body is not in this repo
            source, _ = handler
            artifacts.append(
                CodeArtifact(
                    kind="api_endpoint",
                    path=f"{ep.file}::{ep.function}",
                    content=source,
                    context=inventory,
                )
            )
        return artifacts


def _handler_index(files: dict[str, str]) -> dict[tuple[str, str], tuple[str, tuple[str, ...]]]:
    index: dict[tuple[str, str], tuple[str, tuple[str, ...]]] = {}
    for path, content in files.items():
        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                segment = ast.get_source_segment(content, node)
                if segment:
                    index[(path, node.name)] = (segment, _decorator_names(node))
    return index


def _decorator_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    names = []
    for dec in node.decorator_list:
        func = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(func, ast.Attribute):
            names.append(func.attr)
        elif isinstance(func, ast.Name):
            names.append(func.id)
    return tuple(names)


def _inventory(http: list[Entrypoint], handlers: dict) -> str:
    lines = ["API surface (every endpoint, for architectural consistency, NOT under review):"]
    for ep in http:
        method = ep.method or "-"
        route = ep.route or "-"
        decs = handlers.get((ep.file, ep.function), ("", ()))[1]
        deco = ",".join(decs) if decs else "-"
        lines.append(f"  {method} {route}  ->  {ep.file}::{ep.function}  decorators=[{deco}]")
    return "\n".join(lines)
