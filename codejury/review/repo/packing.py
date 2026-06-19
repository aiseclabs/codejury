"""Focused packing: co-locate the definitions a unit calls or inherits into a small window,
so the reviewer sees the cross-file and inherited code together and judges it in one shot.

A defect whose logic spans a call into another function, file, or inherited base is invisible
to a reviewer that only sees the unit's own text. The fix is not to let the model wander the
tree, that dilutes the context and the model talks itself out of findings. It is to resolve
the called and inherited definitions at pack time and co-locate them in one focused window, the
arrangement that makes the model frame a cross-function defect reliably. Focus is the lever,
not access.

Language-agnostic: it resolves a symbol with the repo's `find_definition`, so it needs no per
language call graph and works the same on a contract, a service, or a handler. Bounded hard, a
cap on definitions and total size, since a window that grows back into the whole tree loses the
focus it exists to create. Pure functions over the filesystem, no model calls.
"""

from __future__ import annotations

import re

from codejury.review.repo import navigation
from codejury.review.repo.paths import safe_repo_path

_MAX_DEFS = 8
_MAX_DEF_LINES = 120
_MAX_TOTAL = 16_000   # the focused-window cap: above this, stop pulling, focus beats coverage

# keywords and common builtins that look like calls or bases but are never a definition worth
# pulling, so a heuristic scan is not flooded with them
_SKIP = {
    "if", "for", "while", "return", "require", "assert", "revert", "emit", "function", "public",
    "private", "internal", "external", "view", "pure", "payable", "memory", "storage", "calldata",
    "returns", "import", "from", "is", "extends", "implements", "class", "def", "new", "await",
    "async", "const", "let", "var", "this", "self", "super", "true", "false", "null", "none",
    "int", "uint", "uint256", "address", "bool", "bytes", "string", "mapping", "struct", "enum",
    "print", "len", "str", "int", "list", "dict", "set", "range", "type", "isinstance",
}


def extract_block(lines: list[str], def_line: int) -> tuple[int, int]:
    """The 1-based line range [start, end] of the definition block at `def_line`. Brace-balanced
    for brace languages, indentation for the rest, capped at `_MAX_DEF_LINES` so one pull stays
    small."""
    n = len(lines)
    start = max(1, min(def_line, n))
    head = lines[start - 1]
    depth = 0
    seen_brace = False
    end = start
    for i in range(start - 1, min(n, start - 1 + _MAX_DEF_LINES)):
        line = lines[i]
        depth += line.count("{") - line.count("}")
        if "{" in line:
            seen_brace = True
        end = i + 1
        if seen_brace and depth <= 0:
            return start, end
    if seen_brace:
        return start, end   # never closed within the cap, return the capped window
    # no braces: use indentation, the block is the lines indented under the def
    base = len(head) - len(head.lstrip())
    end = start
    for i in range(start, min(n, start - 1 + _MAX_DEF_LINES)):
        line = lines[i]
        if not line.strip():
            continue   # a blank line never extends the block, so trailing blanks are trimmed
        if len(line) - len(line.lstrip()) <= base:
            break
        end = i + 1
    return start, end


def referenced_symbols(code: str) -> list[str]:
    """Identifiers the code calls or inherits that may be defined elsewhere, deduped in order.
    Heuristic and language-agnostic, it over-collects and lets `find_definition` filter."""
    out: list[str] = []
    seen: set[str] = set()

    def add(s: str) -> None:
        s = s.strip()
        if s and len(s) > 2 and s.lower() not in _SKIP and s not in seen:
            seen.add(s)
            out.append(s)

    for m in re.finditer(r"\b([A-Za-z_]\w+)\s*\(", code):   # calls
        add(m.group(1))
    for m in re.finditer(r"\b(?:is|extends|implements)\s+([A-Za-z_][\w,\s]*?)[\{\(]", code):  # inheritance
        for part in re.split(r"[,\s]+", m.group(1)):
            add(part)
    return out


def _char_range(lines: list[str], start_line: int, end_line: int) -> tuple[int, int]:
    """Char offsets for a 1-based inclusive line range, the form a unit fragment uses."""
    start_char = sum(len(line) + 1 for line in lines[:start_line - 1])
    end_char = sum(len(line) + 1 for line in lines[:end_line])
    return start_char, end_char


def pack_fragments(root: str, files: tuple[str, ...], *, max_defs: int = _MAX_DEFS,
                   max_total: int = _MAX_TOTAL) -> list[tuple[str, int, int]]:
    """For symbols the owned files reference but do not define, resolve each with find_definition
    and return `(file, start_char, end_char)` fragments of their blocks, bounded so the packed
    window stays focused. A symbol defined in the unit's own files is skipped, it is already
    visible. Definitions in vendored or internal libraries on the path are pulled, that is the
    inherited and called code a single-shot reviewer cannot otherwise see."""
    owned = set(files)
    refs: list[str] = []
    for rel in files:
        path = safe_repo_path(root, rel)
        if path is None or not path.is_file():
            continue
        try:
            refs += referenced_symbols(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            continue
    seen_ref: set[str] = set()
    fragments: list[tuple[str, int, int]] = []
    seen_frag: set[tuple[str, int, int]] = set()
    total = 0
    for sym in refs:
        if sym in seen_ref:
            continue
        seen_ref.add(sym)
        if len(fragments) >= max_defs or total >= max_total:
            break
        for d in navigation.find_definition(root, sym, max_hits=3):
            df = d["file"]
            if df in owned:
                continue   # defined in the unit already, visible
            path = safe_repo_path(root, df)
            if path is None or not path.is_file():
                continue
            try:
                dlines = path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue
            s_line, e_line = extract_block(dlines, d["line"])
            s_char, e_char = _char_range(dlines, s_line, e_line)
            frag = (df, s_char, e_char)
            if frag in seen_frag or e_char - s_char > max_total:
                continue
            if total + (e_char - s_char) > max_total:
                continue
            fragments.append(frag)
            seen_frag.add(frag)
            total += e_char - s_char
            break   # one definition per symbol
    return fragments


def pack_context(root: str, files: tuple[str, ...]) -> str:
    """The co-located called and inherited definitions for a unit, a labeled block to append to
    the unit's own code, or empty when nothing resolves outside the unit."""
    parts: list[str] = []
    for df, s_char, e_char in pack_fragments(root, files):
        path = safe_repo_path(root, df)
        if path is None:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        parts.append(f"# pulled definition from {df}:\n{text[s_char:e_char]}")
    return "\n\n".join(parts)
