"""FunctionSource -- split Python source into one CodeArtifact per function.

Parses the AST and emits an artifact for every function and method (including
async and nested ones), in source order. Good for deeply auditing one handler at
a time. The content must be valid Python; a parse failure raises SyntaxError.
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
        functions.sort(key=lambda n: n.lineno)

        artifacts = []
        for node in functions:
            segment = ast.get_source_segment(self._code, node)
            if segment:
                artifacts.append(
                    CodeArtifact(kind="function", path=f"{self._path}::{node.name}", content=segment)
                )
        return artifacts
