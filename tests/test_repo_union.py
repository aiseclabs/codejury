"""The cross-pass union core: dedup by location, accumulate the union, and converge
only after K consecutive passes add nothing. This is what turns random per-pass
results into a stable, growing-only union."""

from codejury.review.repo.union import Accumulator, Candidate, collapse_colocated, merge


def _c(title, **kw):
    return Candidate(title=title, **kw)


def test_collapse_colocated_merges_same_file_line_class_under_different_endpoints():
    a = _c("freshness", category="replay", endpoint="VerificationController.check",
           file="authorizer/controllers/registrar.py", line=58)
    b = _c("freshness view", category="Replay", endpoint="POST /v1/check_challenge",
           file="authorizer/controllers/registrar.py", line=58)
    pool: dict = {}
    merge(pool, [a, b])
    assert len(pool) == 2
    assert len(collapse_colocated(list(pool.values()))) == 1


def test_collapse_colocated_keeps_distinct_lines_and_classes():
    same_file = "app/v.py"
    cands = [
        _c("a", category="idor", file=same_file, line=10),
        _c("b", category="idor", file=same_file, line=20),
        _c("c", category="replay", file=same_file, line=10),
    ]
    assert len(collapse_colocated(cands)) == 3


def test_collapse_colocated_never_merges_on_file_alone_when_line_missing():
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
    assert merge(pool, [b]) == 0
    assert len(pool) == 1


def test_dedup_falls_back_to_file_plus_category():
    a = _c("exposure", file="app/log.py", category="data-exposure")
    b = _c("exposure dup", file="app/log.py", category="data-exposure")
    c = _c("other", file="app/log.py", category="idor")
    pool: dict = {}
    merge(pool, [a, b, c])
    assert len(pool) == 2


def test_by_file_collapses_one_root_cause_across_functions():
    # the shared-helper case: one defect reported at every caller of a verifier, where the
    # endpoint is a function. By file and class it is one finding, not one per function.
    cands = [
        _c("domain sep at execute", category="signature-replay", endpoint="execute", file="Forwarder.sol"),
        _c("domain sep at verify", category="signature-replay", endpoint="verify", file="Forwarder.sol"),
        _c("domain sep raw", category="signature-replay", endpoint="", file="Forwarder.sol"),
    ]
    pool: dict = {}
    assert merge(pool, cands, by_file=True) == 1
    assert len(pool) == 1


def test_by_file_keeps_distinct_classes_in_one_file():
    a = _c("replay", category="signature-replay", endpoint="execute", file="Forwarder.sol")
    b = _c("missing check", category="access-control", endpoint="verify", file="Forwarder.sol")
    pool: dict = {}
    merge(pool, [a, b], by_file=True)
    assert len(pool) == 2


def test_endpoint_dedup_is_default_when_not_by_file():
    a = _c("a", category="signature-replay", endpoint="execute", file="Forwarder.sol")
    b = _c("b", category="signature-replay", endpoint="verify", file="Forwarder.sol")
    pool: dict = {}
    merge(pool, [a, b])
    assert len(pool) == 2


def test_accumulator_by_file_unions_one_per_file_class():
    acc = Accumulator(converge_after=1, dedup_by_file=True)
    acc.add_pass([_c("at execute", category="signature-replay", endpoint="execute", file="Forwarder.sol")])
    acc.add_pass([_c("at verify", category="signature-replay", endpoint="verify", file="Forwarder.sol")])
    assert len(acc.findings) == 1


def test_confirmed_upgrades_blocked_at_same_location():
    pool: dict = {}
    merge(pool, [_c("x", endpoint="POST /t", status="blocked")])
    merge(pool, [_c("x", endpoint="POST /t", status="confirmed")])
    assert len(pool) == 1
    assert next(iter(pool.values())).status == "confirmed"


def test_union_only_grows_across_passes():
    acc = Accumulator(converge_after=2)
    assert acc.add_pass([_c("a", endpoint="GET /a"), _c("b", endpoint="GET /b")]) == 2
    assert acc.add_pass([_c("b2", endpoint="GET /b"), _c("c", endpoint="GET /c")]) == 1
    assert {f.title for f in acc.findings} == {"a", "b", "c"}


def test_convergence_needs_k_consecutive_empty_passes():
    acc = Accumulator(converge_after=2)
    acc.add_pass([_c("a", endpoint="GET /a")])
    assert not acc.converged
    acc.add_pass([])
    assert not acc.converged
    acc.add_pass([])
    assert acc.converged


def test_a_late_new_finding_resets_convergence():
    acc = Accumulator(converge_after=2)
    acc.add_pass([])
    acc.add_pass([_c("late", endpoint="GET /late")])
    assert not acc.converged


def test_findings_calibrate_severity_by_median_across_passes():
    acc = Accumulator(converge_after=1)
    for sev in ("LOW", "HIGH", "MEDIUM"):
        acc.add_pass([_c("idor", category="idor", endpoint="GET /x/<id>", severity=sev)])
    (f,) = acc.findings
    assert f.severity == "MEDIUM"


def test_findings_apply_firm_rule_floor():
    acc = Accumulator(converge_after=1)
    acc.add_pass([_c("token in log", category="Credential / Secret Exposure",
                     file="a.py", severity="LOW")])
    (f,) = acc.findings
    assert f.severity == "HIGH"
