"""RepoModel: a language-agnostic structural map of a repository.

Lists the repo's files deterministically, with zero model calls, cacheable. It does not
parse code or enumerate framework routes: identifying the actual entrypoints is
left to the agent, guided by the matched language/framework guides under
`knowledge/guides/languages` and `knowledge/guides/frameworks`. The only deterministic help is flagging
*candidate* entrypoint files by the globs a guide declares, which keeps every
language-specific and framework-specific detail in the guides and out of this module.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

from codejury.detection import Detection, load_detection


@dataclass(frozen=True, kw_only=True)
class RepoModel:
    root: str
    files: tuple[str, ...]


def _read_files(root: Path, detection: Detection | None = None) -> tuple[str, ...]:
    """Relative paths of the files under root, skipping noise dirs and symlinks
    that escape the tree."""
    skip_dirs = (detection or load_detection()).skip_dirs
    root = root.resolve()
    out: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(part in skip_dirs for part in rel.parts):
            continue
        try:
            if not path.resolve().is_relative_to(root):
                continue  # symlink escaping the tree
        except OSError:
            continue
        out.append(str(rel))
    return tuple(sorted(out))


def build_repo_model_from_dir(root: str | Path, detection: Detection | None = None) -> RepoModel:
    return RepoModel(root=str(root), files=_read_files(Path(root), detection))


def build_repo_model(root: str | Path, files) -> RepoModel:
    """Build a RepoModel from an iterable of relative paths, for tests or callers
    that already have the file list."""
    return RepoModel(root=str(root), files=tuple(sorted(files)))


_SCAN_MAX_BYTES = 2_000_000


def _read_text(path: Path) -> str:
    try:
        if path.stat().st_size > _SCAN_MAX_BYTES:
            return ""
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def candidate_entrypoint_files(files, *, root=None, globs=(), markers=(), detection: Detection | None = None) -> list[str]:
    """Files likely to define entrypoints. A file is a candidate when its path
    matches one of `globs`, or when `root` is given and its content contains one
    of `markers` the guide declares, such as a handler class or a route
    registration. The marker scan is what recovers framework entrypoints that no
    filename glob would catch, and it stays data-driven because the markers come
    from the guide. Returns a sorted list with no duplicates."""
    det = detection or load_detection()
    globs = tuple(globs)
    markers = tuple(markers)
    base = Path(root) if root is not None else None
    out: list[str] = []
    for f in files:
        if det.is_test_path(f):
            continue
        if any(fnmatch.fnmatch(f, g) for g in globs):
            out.append(f)
            continue
        if markers and base is not None and Path(f).suffix in det.source_extensions:
            text = _read_text(base / f)
            if text and any(m in text for m in markers):
                out.append(f)
    return sorted(dict.fromkeys(out))


def logic_layer_files(files, *, globs=(), detection: Detection | None = None) -> list[str]:
    """Non-test files whose path matches one of the downstream logic-layer globs,
    for example managers, controllers, dao, or services. These are not entrypoints
    but the call targets to trace into from an entrypoint, so a review does not
    stop at the view. Returns a sorted list with no duplicates."""
    det = detection or load_detection()
    globs = tuple(globs)
    out = {f for f in files if not det.is_test_path(f) and any(fnmatch.fnmatch(f, g) for g in globs)}
    return sorted(out)


# A logic-layer file is promoted to its own unit only when it implements a cluster of
# resource-interface methods, not a single one. Two distinct CRUD or rights methods
# co-occurring is a structural signal that the type is a REST resource a generic handler
# dispatches to, which generalizes across frameworks and does not over-promote a file
# that merely happens to define one common method such as `ReadAll`.
_MIN_CLUSTER_METHODS = 2


def promoted_logic_units(files, *, root=None, layer_globs=(), markers=(), detection: Detection | None = None) -> list[str]:
    """Logic-layer files that earn their own review unit rather than being only a trace
    target, because they implement a resource interface, a cluster of the CRUD or rights
    method `markers`, so a generic handler dispatches HTTP straight to them and the file
    is a real entrypoint whose authorization and data-exposure would otherwise be reviewed
    by no dedicated unit. A file counts only when it defines at least
    `_MIN_CLUSTER_METHODS` distinct markers, so a lone common method does not over-promote.
    Empty markers, or no root to scan, promotes nothing, the prior behavior. Returns a
    sorted list with no duplicates."""
    if not markers or root is None:
        return []
    det = detection or load_detection()
    layer_globs = tuple(layer_globs)
    markers = tuple(markers)
    base = Path(root)
    out: list[str] = []
    for f in files:
        if det.is_test_path(f):
            continue
        if not any(fnmatch.fnmatch(f, g) for g in layer_globs):
            continue
        if Path(f).suffix not in det.source_extensions:
            continue
        text = _read_text(base / f)
        if text and sum(1 for m in markers if m in text) >= _MIN_CLUSTER_METHODS:
            out.append(f)
    return sorted(dict.fromkeys(out))
