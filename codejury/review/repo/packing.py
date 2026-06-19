"""Focused packing: co-locate the definitions a unit calls or inherits into a small window,
so the reviewer sees the cross-file and cross-slice code together and judges it in one shot.

A defect whose logic spans a call into another function, file, slice, or inherited base is
invisible to a reviewer that only sees the unit's own text. The fix is not to let the model
wander the tree, that dilutes the context and the model talks itself out of findings. It is to
resolve the called and inherited definitions at pack time and co-locate them in one focused
window, the arrangement that makes the model frame a cross-function defect reliably. Focus is
the lever, not access.

It follows the call chain, not one hop: when a pulled definition itself calls outward, those
callees are resolved too, so a path such as `liquidate` into `_cleanupLoan` into
`_updateAndCheckCollateral` lands whole in one window even when the file is reviewed in slices
and the path crosses a slice boundary. The `visible` ranges tell it what the reviewer already
shows, so it pulls only what the slice omits, including a same-file definition in another slice.

Language-agnostic: it resolves a symbol with the repo's `find_definition`, so it needs no per
language call graph and works the same on a contract, a service, or a handler. Bounded hard, a
cap on definitions and total size, since a window that grows back into the whole tree loses the
focus it exists to create. Pure functions over the filesystem, no model calls.
"""

from __future__ import annotations

import re
from collections import deque
from functools import lru_cache
from pathlib import Path

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


def _default_visible(root: str, files: tuple[str, ...]) -> tuple[tuple[str, int, int], ...]:
    """Each readable file in full, the visible ranges to assume when a caller passes none. This
    keeps a direct `pack_context(root, files)` co-locating only outside-file definitions, the
    behavior before slice-aware packing."""
    ranges: list[tuple[str, int, int]] = []
    for rel in files:
        path = safe_repo_path(root, rel)
        if path is None or not path.is_file():
            continue
        try:
            n = len(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            continue
        ranges.append((rel, 0, n))
    return tuple(ranges)


def _is_shown(rel: str, s_char: int, visible: tuple[tuple[str, int, int], ...]) -> bool:
    """Whether a definition starting at `s_char` in `rel` is already in a visible range, so the
    reviewer sees it without a pull. A same-file definition in another slice is not shown, that
    is the cross-slice code this packer co-locates."""
    return any(vrel == rel and vs <= s_char < ve for vrel, vs, ve in visible)


def pack_fragments(root: str, files: tuple[str, ...],
                   visible: tuple[tuple[str, int, int], ...] | None = None,
                   *, max_defs: int = _MAX_DEFS,
                   max_total: int = _MAX_TOTAL) -> list[tuple[str, int, int]]:
    """For symbols the visible code references but does not already show, resolve each with
    find_definition and return `(file, start_char, end_char)` fragments of their blocks, bounded
    so the packed window stays focused. `visible` is the ranges the reviewer already shows,
    defaulting to whole files. A definition inside a visible range is skipped, it is on screen.
    The chain is followed: a pulled definition's own outward calls are resolved too, so a path
    across functions, files, or slices lands whole. Definitions in vendored or internal libraries
    on the path are pulled, that is the called code a single-shot reviewer cannot otherwise see."""
    if visible is None:
        visible = _default_visible(root, files)
    # only pull definitions in the unit's own languages, so a fuzzy resolve does not co-locate an
    # unrelated dependency in another language, the type-fest .d.ts a Solidity unit must not pull,
    # which would dilute the focused window the packer exists to keep small
    owned_exts = {Path(f).suffix.lower() for f in files if Path(f).suffix}
    queue: deque[str] = deque()
    queued: set[str] = set()
    def enqueue(syms: list[str]) -> None:
        for s in syms:
            if s not in queued:
                queued.add(s)
                queue.append(s)
    for vrel, vs, ve in visible:
        path = safe_repo_path(root, vrel)
        if path is None or not path.is_file():
            continue
        try:
            enqueue(referenced_symbols(path.read_text(encoding="utf-8")[vs:ve]))
        except (OSError, UnicodeDecodeError):
            continue
    fragments: list[tuple[str, int, int]] = []
    seen_frag: set[tuple[str, int, int]] = set()
    total = 0
    while queue:
        if len(fragments) >= max_defs or total >= max_total:
            break
        sym = queue.popleft()
        # in-project only: co-locate cross-file and cross-function code in the project, fast.
        # Resolving into a large vendored tree per symbol is too slow for a per-unit packer, so
        # the inherited-from-dependency case is left to a separate, import-scoped resolver.
        for d in navigation.find_definition(root, sym, max_hits=3, include_deps=False):
            df = d["file"]
            if owned_exts and Path(df).suffix.lower() not in owned_exts:
                continue   # a different language, a fuzzy match into an unrelated dep, skip
            path = safe_repo_path(root, df)
            if path is None or not path.is_file():
                continue
            try:
                dtext = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            dlines = dtext.splitlines()
            s_line, e_line = extract_block(dlines, d["line"])
            s_char, e_char = _char_range(dlines, s_line, e_line)
            if _is_shown(df, s_char, visible):
                continue   # already on screen in a visible slice
            frag = (df, s_char, e_char)
            if frag in seen_frag or e_char - s_char > max_total:
                continue
            if total + (e_char - s_char) > max_total:
                continue
            fragments.append(frag)
            seen_frag.add(frag)
            total += e_char - s_char
            # follow the chain: the pulled body's own calls may be the next link off-slice.
            # Enqueuing only on a pull bounds growth to the callees of at most max_defs defs.
            enqueue(referenced_symbols(dtext[s_char:e_char]))
            break   # one definition per symbol
    return fragments


@lru_cache(maxsize=512)
def pack_context(root: str, files: tuple[str, ...],
                 visible: tuple[tuple[str, int, int], ...] | None = None) -> str:
    """The co-located called and inherited definitions for a unit, a labeled block to append to
    the unit's own code, or empty when nothing resolves outside what the reviewer shows. `visible`
    is the ranges already on screen, so a slice unit pulls the off-slice code it omits. Cached per
    unit, since it is deterministic and the same unit is reviewed across many passes and models."""
    parts: list[str] = []
    for df, s_char, e_char in pack_fragments(root, files, visible):
        path = safe_repo_path(root, df)
        if path is None:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        parts.append(f"# pulled definition from {df}:\n{text[s_char:e_char]}")
    return "\n\n".join(parts)
