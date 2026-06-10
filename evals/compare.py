"""Compare two eval results, the heart of judging a change.

A single score cannot tell an improvement from noise between runs, the review is not
deterministic. The standard is a move that holds across repeated runs: recall up or level
and precision level or up, beyond the noise band, with the per-issue flips naming exactly
which planted issues were newly caught or newly lost. This reads two `Result` json files
and reports those flips and the deltas, so a knowledge or prompt change is judged on what
actually moved, not on one aggregate number.
"""

from __future__ import annotations

import json
from pathlib import Path


def _load(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def compare(before: dict, after: dict) -> dict:
    bf, af = set(before.get("found", [])), set(after.get("found", []))
    bfp, afp = set(before.get("false_positives", [])), set(after.get("false_positives", []))
    return {
        "target": after.get("target", before.get("target", "")),
        "recall_before": before.get("recall", 0.0),
        "recall_after": after.get("recall", 0.0),
        "precision_before": before.get("precision_known", 0.0),
        "precision_after": after.get("precision_known", 0.0),
        "newly_found": sorted(af - bf),
        "newly_missed": sorted(bf - af),
        "newly_false_positive": sorted(afp - bfp),
        "fixed_false_positive": sorted(bfp - afp),
    }


def format_compare(d: dict) -> str:
    lines = [f"=== compare: {d['target']} ===",
             f"  recall    {d['recall_before']:.0%} -> {d['recall_after']:.0%}",
             f"  precision {d['precision_before']:.0%} -> {d['precision_after']:.0%}"]
    for label, key in (("newly found", "newly_found"), ("newly MISSED", "newly_missed"),
                       ("new false positive", "newly_false_positive"),
                       ("fixed false positive", "fixed_false_positive")):
        if d[key]:
            lines.append(f"  {label}: {', '.join(d[key])}")
    return "\n".join(lines)


def compare_files(before: str | Path, after: str | Path) -> dict:
    return compare(_load(before), _load(after))
