"""The one boundary for reading a reviewed repository's files from a path that may be untrusted.

A candidate's `file` can come from model output during a run or from a workspace
`candidates/*.md` a prompt-injected agent or a manual edit wrote. Joined naively, an absolute
path discards the root and a `../` segment escapes it, so the verifier could read and then
ship a file outside the target repository to the provider. Every workspace-to-source read goes
through `safe_repository_path`, which resolves under the root and refuses anything that escapes,
mirroring the symlink containment the repository file map already applies.
"""

from __future__ import annotations

from pathlib import Path


def safe_repository_path(root: str | Path, rel: str) -> Path | None:
    """Resolve `rel` under `root`, or None when it is empty, absolute, parent-traversing,
    or escapes root through a symlink. The single gate for reading a reviewed repository's files
    from a path that may come from model output or a workspace file."""
    if not rel:
        return None
    base = Path(root).resolve()
    try:
        resolved = (base / rel).resolve()
    except OSError:
        return None
    return resolved if resolved.is_relative_to(base) else None


def is_unsafe_rel(rel: str) -> bool:
    """A relative path that should never name a finding's location: empty, absolute, or
    carrying a `..` segment. Used to drop a tampered or hallucinated location before it
    becomes a reportable finding, independent of whether the file exists."""
    if not rel:
        return True
    p = Path(rel)
    return p.is_absolute() or ".." in p.parts
