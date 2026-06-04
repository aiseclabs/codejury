# Security Review Memory: <project>

> Maintained by the security-review agent and carried across runs. Read at the
> start of every run, updated at the end. It skips confirmed false positives, does
> not re-litigate confirmed findings, avoids re-reporting fixed issues, and focuses
> on historically risky areas. This is how repeated runs converge instead of
> re-deriving from zero.

## Confirmed False Positives

<!-- FP-001 <short description>
- Date: YYYY-MM-DD
- Path/pattern: `tests/` or `apps/payment/mock_*.py`
- Type: sql_injection / auth_bypass / ...
- Why not a real issue: <reason, cite the controlling fact, for example the lock holds>
-->

## Confirmed Findings

<!-- Real findings already settled in a prior run. Carry them forward, do not
re-investigate from scratch, re-list them in the report.
CF-001 <issue title>
- Issue: `issues/<name>.md`
- Status: confirmed | blocked
-->

## Fixed

<!-- FIXED-001 <issue title>
- Date / commit: YYYY-MM-DD / abc1234
- Original issue: <summary>
-->

## High-Risk Areas

<!-- - `<path>`: <reason, for example a past auth bypass> -->

## Audit History

| Date | Mode | HIGH | MEDIUM | Notes |
|------|------|------|--------|-------|
