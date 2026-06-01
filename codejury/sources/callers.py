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


def _symbol_sources(files: dict[str, str]) -> dict[str, list[tuple[str, str]]]:
    """Map each defined function/class/method name to its (path, source) definitions."""
    out: dict[str, list[tuple[str, str]]] = {}
    for path, content in files.items():
        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                src = ast.get_source_segment(content, node)
                if src:
                    out.setdefault(node.name, []).append((path, src))
    return out


def _called_names(content: str) -> set[str]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                names.add(func.id)
            elif isinstance(func, ast.Attribute):
                names.add(func.attr)
    return names


def callee_context(target_path: str, files: dict[str, str], *, max_chars: int = 12_000) -> str:
    """Source of functions that `target_path` calls but that are defined in other files.

    This is the forward direction -- it puts the called code (where a vulnerability
    often lives, e.g. a manager a view delegates to) in front of the verifier, which
    single-file review cannot see.
    """
    symbols = _symbol_sources(files)
    own = defined_names(files.get(target_path, ""))
    blocks: list[str] = []
    total = 0
    for name in sorted(_called_names(files.get(target_path, ""))):
        if name in own:
            continue
        for path, src in symbols.get(name, []):
            if path == target_path:
                continue
            block = f"# {path} -> {name}\n{src}"
            if total + len(block) > max_chars:
                return "\n\n".join(blocks)
            blocks.append(block)
            total += len(block)
            break  # one definition per called name is enough context
    return "\n\n".join(blocks)


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
