"""The cross-pass union core: dedup by location, accumulate the union, and converge
only after K consecutive passes add nothing. This is what turns random per-pass
results into a stable, growing-only union."""

from codejury.review.repo.union import Accumulator, Candidate, collapse_colocated, merge


def _c(title, **kw):
    return Candidate(title=title, **kw)


def test_collapse_colocated_merges_same_file_line_class_under_different_endpoints():
    # two lenses label one defect with different endpoint prose, so endpoint dedup
    # keeps both, but they cite the same file:line:class, so they are one finding
    a = _c("freshness", category="replay", endpoint="VerificationController.check",
           file="authorizer/controllers/registrar.py", line=58)
    b = _c("freshness view", category="Replay", endpoint="POST /v1/check_challenge",
           file="authorizer/controllers/registrar.py", line=58)
    pool: dict = {}
    merge(pool, [a, b])
    assert len(pool) == 2                       # endpoint dedup keeps both
    assert len(collapse_colocated(list(pool.values()))) == 1   # file:line:class collapses them


def test_collapse_colocated_keeps_distinct_lines_and_classes():
    same_file = "app/v.py"
    cands = [
        _c("a", category="idor", file=same_file, line=10),
        _c("b", category="idor", file=same_file, line=20),     # different line, distinct
        _c("c", category="replay", file=same_file, line=10),   # different class, distinct
    ]
    assert len(collapse_colocated(cands)) == 3


def test_collapse_colocated_never_merges_on_file_alone_when_line_missing():
    # no parsed line means we cannot assert it is the same defect, so keep both, recall first
    cands = [
        _c("a", category="idor", file="app/v.py"),
        _c("b", category="idor", file="app/v.py"),
    ]
    assert len(collapse_colocated(cands)) == 2


def test_dedup_by_endpoint_normalizes_path_params():
    a = _c("idor", endpoint="GET /withdrawals/<wid>")
    b = _c("idor again", endpoint="get /withdrawals/{id}")
    pool: dict = {}
    assert merge(pool, [a]) == 1
    assert merge(pool, [b]) == 0          # same endpoint after normalization
    assert len(pool) == 1


def test_dedup_falls_back_to_file_plus_category():
    a = _c("exposure", file="app/log.py", category="data-exposure")
    b = _c("exposure dup", file="app/log.py", category="data-exposure")
    c = _c("other", file="app/log.py", category="idor")
    pool: dict = {}
    merge(pool, [a, b, c])
    assert len(pool) == 2                 # a==b, c distinct by category


def test_confirmed_upgrades_blocked_at_same_location():
    pool: dict = {}
    merge(pool, [_c("x", endpoint="POST /t", status="blocked")])
    merge(pool, [_c("x", endpoint="POST /t", status="confirmed")])
    assert len(pool) == 1
    assert next(iter(pool.values())).status == "confirmed"


def test_union_only_grows_across_passes():
    acc = Accumulator(converge_after=2)
    assert acc.add_pass([_c("a", endpoint="GET /a"), _c("b", endpoint="GET /b")]) == 2
    assert acc.add_pass([_c("b2", endpoint="GET /b"), _c("c", endpoint="GET /c")]) == 1  # b dup, c new
    assert {f.title for f in acc.findings} == {"a", "b", "c"}


def test_convergence_needs_k_consecutive_empty_passes():
    acc = Accumulator(converge_after=2)
    acc.add_pass([_c("a", endpoint="GET /a")])   # +1
    assert not acc.converged
    acc.add_pass([])                             # +0, only one empty
    assert not acc.converged
    acc.add_pass([])                             # +0, two consecutive empty
    assert acc.converged


def test_a_late_new_finding_resets_convergence():
    acc = Accumulator(converge_after=2)
    acc.add_pass([])
    acc.add_pass([_c("late", endpoint="GET /late")])  # new finding on an otherwise quiet run
    assert not acc.converged                          # the union grew, keep going
