"""Shared eval core: the answer key schema, report matching, and recall and precision.

The ruler measures a review by comparing its reports against an answer key, the planted
issues a complete review must surface and the safe lookalikes a report would be a false
positive on. This module owns the parts both eval paths share: loading and validating an
answer key, matching a report to a key entry, and turning the matches into a Result. The
diff path and the repo path differ only in how they produce the reports, see diff.py and
repo.py, so all of the scoring math lives here once.

The answer key never reaches the review under test, so a high score cannot come from the
review reading the key. Matching is primarily by entry, the endpoint a report cites,
normalized so a mount prefix and path param syntax do not matter, with the cited file and
the category as the soft fallback for a class an endpoint does not anchor.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

# loose map from a freeform category or type string to a ledger category, a soft signal
_CATEGORY_HINTS = {
    "insecure-direct-object-reference": ("idor", "direct object", "insecure-direct"),
    "missing-authorization": ("missing auth", "authorization", "authz", "access control", "broken access"),
    "replay-attack": ("replay",),
    "mass-assignment": ("mass assignment", "mass-assignment"),
    "auth-bypass": ("auth bypass", "authentication bypass"),
}

_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def normalize_endpoint(text: str) -> str:
    """Normalize an endpoint so GET /wallets/<wallet_id> and get /wallets/{id} match."""
    text = text.strip().strip("`").lower()
    text = re.sub(r"[<{][^>}]*[>}]", "*", text)
    text = re.sub(r"\s+", " ", text)
    return text


def _split_endpoint(text: str) -> tuple[str, list[str]]:
    """Split a normalized endpoint into a method and its path segments."""
    parts = normalize_endpoint(text).split(" ", 1)
    if len(parts) == 2 and parts[0] in _METHODS:
        method, path = parts[0], parts[1]
    else:
        method, path = "", parts[-1]
    return method, [s for s in path.strip("/").split("/") if s]


def endpoint_match(report_ep: str, key_entry: str) -> bool:
    """Match by method and path, where either path may carry a mount prefix the other
    omits, so a real repo's /api/v1/memories/*/update matches a key entry of
    /memories/*/update. Methods must agree when both are present, and one path's segments
    must be a suffix of the other's, with a path param matching any concrete segment."""
    rm, rseg = _split_endpoint(report_ep)
    km, kseg = _split_endpoint(key_entry)
    if rm and km and rm != km:
        return False
    n = min(len(rseg), len(kseg))
    if n == 0:
        return False
    return all(a == b or a == "*" or b == "*" for a, b in zip(rseg[-n:], kseg[-n:]))


def category_of(text: str) -> str:
    low = text.lower()
    for cat, hints in _CATEGORY_HINTS.items():
        if any(h in low for h in hints):
            return cat
    return low.strip()


@dataclass(frozen=True, kw_only=True)
class Report:
    """One reported issue, however a path produced it. Endpoint is stored normalized."""
    name: str
    endpoint: str = ""
    category: str = ""
    files: tuple[str, ...] = ()

    @classmethod
    def make(cls, name: str, endpoint: str, category: str, files) -> "Report":
        return cls(name=name, endpoint=normalize_endpoint(endpoint),
                   category=category_of(category), files=tuple(files))


@dataclass(frozen=True, kw_only=True)
class KeyEntry:
    """A planted issue or a safe lookalike from the answer key."""
    id: str
    entry: str = ""
    file: str = ""
    category: str = ""
    severity: str = ""
    note: str = ""


@dataclass(frozen=True, kw_only=True)
class AnswerKey:
    target: str
    planted: tuple[KeyEntry, ...]
    safe: tuple[KeyEntry, ...]


def _key_entries(rows, *, require_category: bool, where: str) -> tuple[KeyEntry, ...]:
    out: list[KeyEntry] = []
    for i, r in enumerate(rows or []):
        if not isinstance(r, dict):
            raise ValueError(f"{where}[{i}] is not a mapping")
        if "entry" not in r and "file" not in r:
            # invariant: no location means a report can never be matched to it, so a key
            # entry with neither an endpoint nor a file is unscoreable and is rejected loud
            raise ValueError(f"{where}[{i}] has neither entry nor file, it cannot be matched")
        if require_category and not r.get("category"):
            raise ValueError(f"{where}[{i}] has no category")
        out.append(KeyEntry(
            id=str(r.get("id") or f"{where}-{i}"),
            entry=str(r.get("entry", "")),
            file=str(r.get("file", "")),
            category=category_of(str(r.get("category", ""))),
            severity=str(r.get("severity", "")),
            note=str(r.get("note", "")),
        ))
    return tuple(out)


def load_answer_key(path: str | Path) -> AnswerKey:
    """Load and validate an answer key, failing loud on a malformed one rather than
    scoring against a silently empty key. Accepts `planted:` and the legacy `issues:` as
    aliases, so a key authored before the rename loads unchanged."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"answer key {path} is not a mapping")
    planted_rows = data.get("planted", data.get("issues"))
    if planted_rows is None:
        raise ValueError(f"answer key {path} has no planted (or legacy issues) list")
    return AnswerKey(
        target=str(data.get("target", Path(path).stem)),
        planted=_key_entries(planted_rows, require_category=True, where="planted"),
        safe=_key_entries(data.get("safe"), require_category=False, where="safe"),
    )


def _matches(report: Report, entry: KeyEntry) -> bool:
    # endpoint is the precise signal: when the key entry cites one, the report must match
    # it exactly, no loose file fallback that would credit a report on a sibling endpoint
    if entry.entry:
        return bool(report.endpoint) and endpoint_match(report.endpoint, entry.entry)
    # no endpoint on the key entry, fall back to the same file and a matching category,
    # for a class such as data exposure that an endpoint does not anchor
    file_hit = any(Path(f).name == Path(entry.file).name for f in report.files)
    return file_hit and bool(entry.category) and report.category == entry.category


@dataclass(kw_only=True)
class Result:
    """The score of one review against one answer key, JSON-serializable for compare."""
    target: str
    found: list[str] = field(default_factory=list)
    missed: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)
    n_planted: int = 0
    n_reports: int = 0
    errors: int = 0   # review or engine calls that failed, counted not hidden, invariant 3

    @property
    def recall(self) -> float:
        return len(self.found) / self.n_planted if self.n_planted else 0.0

    @property
    def precision_known(self) -> float:
        """Real reports over reports that landed on a known entry, planted or safe. An
        extra report is excluded since the key cannot say whether it is a real bug."""
        known = len(self.found) + len(self.false_positives)
        return len(self.found) / known if known else 1.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["recall"] = round(self.recall, 4)
        d["precision_known"] = round(self.precision_known, 4)
        return d


def score(key: AnswerKey, reports: list[Report]) -> Result:
    """Score reports against an answer key. A planted issue is found when some report
    matches it. A report that matches a safe lookalike is a false positive. A report that
    matches neither is extra, recorded for a human since it may be a real bug the key
    misses rather than noise."""
    res = Result(target=key.target, n_planted=len(key.planted), n_reports=len(reports))
    matched_reports: set[str] = set()
    for p in key.planted:
        hit = next((r for r in reports if _matches(r, p)), None)
        if hit is not None:
            res.found.append(p.id)
            matched_reports.add(hit.name)
        else:
            res.missed.append(p.id)
    for s in key.safe:
        for r in reports:
            if _matches(r, s):
                res.false_positives.append(r.name)
                matched_reports.add(r.name)
    res.extra = [r.name for r in reports if r.name not in matched_reports]
    return res
