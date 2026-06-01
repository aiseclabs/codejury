"""Lightweight cross-file caller context.

For a file under review, find where the functions and classes it defines are
called elsewhere in the repository. Showing those call sites lets the verifier
trace where an argument comes from -- which is exactly what single-file review
lacks for taint-style issues (a path/command that is operator-supplied vs
attacker-controlled). This is a textual usage finder, not a full call graph.
"""

from __future__ import annotations

import ast
import re


def defined_names(content: str) -> set[str]:
    """Top-level function and class names defined in `content`."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return set()
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }


def caller_context(target_path: str, files: dict[str, str], *, max_lines: int = 30) -> str:
    """Lines elsewhere in `files` that call the names defined in `target_path`."""
    names = defined_names(files.get(target_path, ""))
    if not names:
        return ""
    # word-boundary call: `name(` not preceded/followed by other identifier chars
    call = re.compile(r"\b(?:" + "|".join(re.escape(n) for n in names) + r")\s*\(")

    hits: list[str] = []
    for path in sorted(files):
        if path == target_path:
            continue
        for lineno, line in enumerate(files[path].splitlines(), 1):
            if call.search(line):
                hits.append(f"{path}:{lineno}: {line.strip()}")
                if len(hits) >= max_lines:
                    return "\n".join(hits)
    return "\n".join(hits)
