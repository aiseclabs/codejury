"""Benchmark discovery: the public benchmarks in the repo plus private sources from a
local, uncommitted config, so private targets and keys never enter the public repo.

The repo ships only public OSS benchmarks under `evals/benchmarks`. Private benchmarks
stay wherever they already live: a local config, gitignored, lists their sources as a
path or a private git repo, and they plug in under the same names. Nothing private moves
into the repo and nothing private commits. A source root may use the new per-benchmark
layout, `repo/<name>/answer_key.yaml`, or the legacy `groundtruth/<name>.yaml`, so an
existing private benchmark scores without being reshaped.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import yaml

_HERE = Path(__file__).resolve().parent
_PUBLIC = _HERE / "benchmarks"
_CACHE = Path.home() / ".cache" / "codejury" / "eval-sources"


def _config_path() -> Path | None:
    override = os.environ.get("CODEJURY_EVAL_CONFIG")
    if override:
        return Path(override)
    local = _HERE / "local.yaml"
    return local if local.is_file() else None


def _clone(repo: str, ref: str | None) -> Path:
    """Clone or update a private benchmark repo into the cache, so a private source can be
    a git url rather than a path in the repo. Network and credentials are the operator's."""
    slug = "".join(c if c.isalnum() else "-" for c in repo).strip("-")
    dest = _CACHE / slug
    if dest.is_dir():
        subprocess.run(["git", "-C", str(dest), "pull", "--ff-only"], check=True, capture_output=True)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        cmd = ["git", "clone", "--depth", "1"]
        if ref:
            cmd += ["--branch", ref]
        cmd += [repo, str(dest)]
        subprocess.run(cmd, check=True, capture_output=True)
    return dest


def source_roots() -> list[Path]:
    """The roots to search, public first, then each private source from the local config."""
    roots = [_PUBLIC]
    cfg = _config_path()
    if cfg is None:
        return roots
    data = yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
    for src in data.get("benchmark_sources", []):
        if "path" in src:
            roots.append(Path(src["path"]).expanduser())
        elif "repo" in src:
            roots.append(_clone(src["repo"], src.get("ref")))
        else:
            raise ValueError(f"benchmark source {src} has neither path nor repo")
    return roots


def find_answer_key(name: str) -> Path:
    """Locate an answer key by name across the public root and the configured sources,
    new layout first then legacy. Fails loud listing where it looked, so a typo or an
    unconfigured private source is obvious rather than a silent empty score."""
    searched: list[str] = []
    for root in source_roots():
        new = root / "repo" / name / "answer_key.yaml"
        legacy = root / "groundtruth" / f"{name}.yaml"
        searched += [str(new), str(legacy)]
        if new.is_file():
            return new
        if legacy.is_file():
            return legacy
    raise ValueError(f"no answer key for '{name}'. Looked in:\n  " + "\n  ".join(searched))
