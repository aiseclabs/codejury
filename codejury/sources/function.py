"""FunctionSource: split Python source into one CodeArtifact per function.

Parses the AST and emits an artifact for every top-level function and method,
async included, in source order. Functions nested inside another function are
skipped: their source already lives inside the enclosing function's artifact, so
emitting them again would send the model overlapping, duplicated content. The
content must be valid Python; a parse failure raises SyntaxError.
"""

from __future__ import annotations

import ast

from codejury.domain.artifact import CodeArtifact
from codejury.sources.base import Source


class FunctionSource(Source):
    def __init__(self, code: str, *, path: str = "<source>") -> None:
        self._code = code
        self._path = path

    def list_artifacts(self) -> list[CodeArtifact]:
        tree = ast.parse(self._code)
        functions = [
            node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        functions = [n for n in functions if not _nested_in_function(n, functions)]
        functions.sort(key=lambda n: n.lineno)

        artifacts = []
        for node in functions:
            segment = ast.get_source_segment(self._code, node)
            if segment:
                artifacts.append(
                    CodeArtifact(kind="function", path=f"{self._path}::{node.name}", content=segment)
                )
        return artifacts


def _nested_in_function(node: ast.AST, functions: list[ast.AST]) -> bool:
    """True if ``node`` is defined inside another function. A method in a class is
    not, since its enclosing scope is the class, not a function."""
    return any(other is not node and any(d is node for d in ast.walk(other)) for other in functions)
