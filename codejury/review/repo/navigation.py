"""Code-navigation tools for an agentic reviewer: read a file, grep the repo, and resolve a
symbol's definition. The seam that lets a reviewer audit like a human, following a call into
the implementation it invokes instead of judging a fixed text bundle. A single model call
sees only the code packed into its prompt, so a cross-file or inherited defect is invisible
to it. These tools let the reviewer fetch the called code on demand, scoped to the reviewed
repo.

Every path goes through `safe_repo_path`, so a tool can never read outside the repo root,
the same containment the verifier uses. Results are bounded, a grep caps its hits and a read
caps its bytes, so one tool call cannot flood the context or stall on a huge tree.

Pure functions over the filesystem, no model calls, fully testable.
"""

from __future__ import annotations

import re
from pathlib import Path

from codejury.review.repo.paths import safe_repo_path

_READ_MAX = 20_000
_GREP_MAX_HITS = 60
_GREP_MAX_FILES = 20_000
_FILE_MAX_BYTES = 2_000_000
# vendored dependency and noise directories. Skipped for a plain grep so a search is not
# drowned by library code, but searched when resolving a definition, since a called method's
# implementation may legitimately live in an internal or vendored library on the call path.
_DEP_DIRS = {"node_modules", ".venv", "venv", "site-packages", "vendor", "dist", "build"}
_NOISE_DIRS = {".git", "__pycache__", ".mypy_cache", ".pytest_cache", ".tox"}
_TEXT_EXT = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".php", ".java", ".kt", ".cs",
    ".sol", ".rs", ".c", ".h", ".cpp", ".hpp", ".scala", ".swift", ".sql", ".sh", ".vy",
}


def read_file(root: str, rel: str, start: int | None = None, end: int | None = None) -> str:
    """Read a file under the repo root, optionally a line range, returned with line numbers.
    Returns an error marker, never raises, so a bad path or a binary file is a tool result the
    reviewer can react to, not a crash."""
    path = safe_repo_path(root, rel)
    if path is None or not path.is_file():
        return f"[not found or outside repo: {rel}]"
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return f"[unreadable: {rel}]"
    lines = text.splitlines()
    lo = max(1, start) if start else 1
    hi = min(len(lines), end) if end else len(lines)
    out: list[str] = []
    size = 0
    for n in range(lo, hi + 1):
        line = f"{n}\t{lines[n - 1]}"
        size += len(line) + 1
        if size > _READ_MAX:
            out.append(f"[truncated at {_READ_MAX} chars]")
            break
        out.append(line)
    return "\n".join(out)


def _iter_files(base: Path, include_deps: bool):
    """Walk the repo's text source files, skipping noise always and vendored deps unless asked.
    Bounded by a file cap so a huge tree cannot stall a search."""
    skip = _NOISE_DIRS if include_deps else _NOISE_DIRS | _DEP_DIRS
    seen = 0
    for path in base.rglob("*"):
        if seen >= _GREP_MAX_FILES:
            break
        if any(part in skip for part in path.parts):
            continue
        if not path.is_file() or path.suffix.lower() not in _TEXT_EXT:
            continue
        try:
            if path.stat().st_size > _FILE_MAX_BYTES:
                continue
        except OSError:
            continue
        seen += 1
        yield path


def grep(root: str, pattern: str, *, include_deps: bool = False, max_hits: int = _GREP_MAX_HITS) -> list[dict]:
    """Search the repo's source for `pattern`, returning capped `{file, line, text}` hits. A
    bad regex falls back to a literal search, so the tool never errors on the reviewer's input."""
    base = Path(root).resolve()
    if not base.is_dir():
        return []
    try:
        rx = re.compile(pattern)
    except re.error:
        rx = re.compile(re.escape(pattern))
    hits: list[dict] = []
    for path in _iter_files(base, include_deps):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        rel = str(path.relative_to(base))
        for i, line in enumerate(text.splitlines(), 1):
            if rx.search(line):
                hits.append({"file": rel, "line": i, "text": line.strip()[:200]})
                if len(hits) >= max_hits:
                    return hits
    return hits


def find_definition(root: str, symbol: str, *, max_hits: int = 20) -> list[dict]:
    """Resolve where `symbol` is defined, the go-to-definition a human follows. Heuristic and
    language-agnostic: it matches the common definition forms across languages, and it searches
    vendored deps too, since a called method on the path may be defined in an internal or
    vendored library. Returns capped `{file, line, text}` hits, the reviewer reads the file to
    confirm."""
    ident = re.escape(symbol.strip())
    if not ident:
        return []
    # def f / function f / class f / contract f / library f / func f / f = function / f: function
    pattern = (
        rf"(\b(def|function|func|class|contract|library|interface|struct|type|fn)\s+{ident}\b)"
        rf"|(\b{ident}\s*[:=]\s*(function|async|\()).*"
        rf"|(\b{ident}\s*\([^)]*\)\s*(public|private|internal|external|returns|\{{))"
    )
    return grep(root, pattern, include_deps=True, max_hits=max_hits)
