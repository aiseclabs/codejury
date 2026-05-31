"""DiffSource -- turn a unified diff into one CodeArtifact per changed file.

Splits on ``diff --git`` headers (falling back to a single section for a plain
diff with no git header). The path is taken from the +++ line, then the ---
line, then the header -- skipping /dev/null so adds and deletes still resolve to
the real file.
"""

from __future__ import annotations

from codejury.domain.artifact import CodeArtifact
from codejury.sources.base import Source


class DiffSource(Source):
    def __init__(self, diff_text: str) -> None:
        self._diff_text = diff_text

    def list_artifacts(self) -> list[CodeArtifact]:
        return [
            CodeArtifact(kind="diff", path=path, content=body)
            for path, body in _split_by_file(self._diff_text)
        ]


def _split_by_file(diff_text: str) -> list[tuple[str, str]]:
    if not diff_text.strip():
        return []

    sections: list[list[str]] = []
    current: list[str] = []
    for line in diff_text.splitlines(keepends=True):
        if line.startswith("diff --git ") and current:
            sections.append(current)
            current = []
        current.append(line)
    if current:
        sections.append(current)

    out: list[tuple[str, str]] = []
    for section in sections:
        path = _path_for(section)
        if path:
            out.append((path, "".join(section)))
    return out


def _path_for(lines: list[str]) -> str:
    plus = minus = header = None
    for line in lines:
        if line.startswith("+++ "):
            plus = _clean(line[4:])
        elif line.startswith("--- "):
            minus = _clean(line[4:])
        elif line.startswith("diff --git "):
            parts = line.split()
            if len(parts) >= 4:
                header = _clean(parts[3])
    for candidate in (plus, minus, header):
        if candidate and candidate != "/dev/null":
            return candidate
    return ""


def _clean(path: str) -> str:
    path = path.split("\t")[0].strip()  # drop trailing timestamp from plain `diff -u`
    if path.startswith(("a/", "b/")):
        path = path[2:]
    return path
