# Architecture and Trust Boundaries

Whole-repository design review. You are given an inventory of the repository:
its files and its entrypoints (the HTTP routes and CLI commands where external
input enters), not the line-by-line code. Judge the shape of the attack surface
and the trust boundaries, not single-line bugs. Point vulnerabilities belong to
their own skill; per-endpoint authorization consistency belongs to api_design.
This skill fires on repository-level design concerns that only the whole surface
reveals.

## Dimensions to rule on

Output one verdict per dimension below (SECURE, VULNERABLE, PARTIAL, NOT_PRESENT,
or UNKNOWN). Use the dimension name as the verdict's `dimension`. Cite the
entrypoint or file as evidence for any VULNERABLE or PARTIAL verdict.

### trust_boundaries

The entrypoints are the trust boundary: every one takes external input. Look at
the surface as a whole.

Secure (support a SECURE verdict):
- The externally reachable surface is small and deliberate, and state-changing
  routes (POST, PUT, PATCH, DELETE) are uniformly behind authentication and
  authorization. Why it is safe: there is no unguarded sibling for an attacker to
  pivot to.

Vulnerable (support a VULNERABLE verdict):
- [MEDIUM CWE-657] The surface mixes guarded and unguarded state-changing routes,
  or exposes privileged or destructive actions (admin, delete, transfer, deploy)
  as entrypoints without an evident trust boundary. Why it is a problem: the
  inconsistency is the hole, and a privileged action reachable from the edge is a
  high-value target.

### attack_surface

Secure (support a SECURE verdict):
- The number and kind of entrypoints match what the application is for, with no
  surprising or debug or internal routes exposed. Why it is safe: a minimal
  surface is less to defend and less to get wrong.

Vulnerable (support a VULNERABLE verdict):
- [MEDIUM CWE-657] The surface includes entrypoints that look internal, debug,
  or administrative and should not be externally reachable, or the surface is far
  larger than the stated purpose warrants. Why it is a problem: each extra
  entrypoint is attackable, and internal or debug routes often skip the controls
  the main surface enforces.

## Judgement notes

- You are reviewing design, not implementation. Prefer architectural verdicts
  (surface shape, boundary consistency) over anything that needs the handler
  body, which later stages review.
- Cite the relevant route or file as the evidence location for any problem.
