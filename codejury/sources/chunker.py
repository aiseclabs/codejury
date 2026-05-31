"""Chunker -- split oversized file content so each artifact fits a context budget.

Splits on line boundaries into pieces of at most ``max_chars``. Small content is
returned unchanged as a single chunk keeping its path; split content gets a
``path#N`` suffix per chunk. A single line longer than the budget becomes its own
(over-budget) chunk rather than being cut mid-line.
"""

from __future__ import annotations


class Chunker:
    def __init__(self, max_chars: int = 8000) -> None:
        self._max_chars = max_chars

    def split(self, path: str, content: str) -> list[tuple[str, str]]:
        if len(content) <= self._max_chars:
            return [(path, content)]

        chunks: list[tuple[str, str]] = []
        buffer: list[str] = []
        size = 0
        index = 1
        for line in content.splitlines(keepends=True):
            if buffer and size + len(line) > self._max_chars:
                chunks.append((f"{path}#{index}", "".join(buffer)))
                index += 1
                buffer, size = [], 0
            buffer.append(line)
            size += len(line)
        if buffer:
            chunks.append((f"{path}#{index}", "".join(buffer)))
        return chunks
