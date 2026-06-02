# Full Security Review — Agent Methodology

A whole-repository security audit, run by an interactive coding agent (Claude
Code, Codex, etc.), not a one-shot LLM call. It traverses the codebase from its
API entrypoints, reasons across files, verifies issues with a real PoC, and
iterates over multiple rounds with a persistent memory. One round is roughly
30 minutes; run as many rounds as needed.

Target repository: the directory you were given.
Workspace: `<workspace>/<project>/` (created for you), holding `api/`,
`issues/`, `analysis/`, and `security-review-memory.md`.

---

## On start (do this first)

1. Read `security-review-memory.md` in the workspace if it exists:
   - skip every pattern under "Confirmed false positives";
   - do not re-report anything under "Fixed";
   - weight the files under "High-risk areas" more heavily.
2. Read `api/_entrypoints.md` (seeded for you from a deterministic scan) as the
   starting map of HTTP routes and CLI commands.
3. Read the relevant rule files under the shipped `rules/` for the target's stack
   (sql-injection, idor, ssrf, authentication-jwt, insecure-deserialization, ...).

## Analysis

Start from the API entrypoints and read the implementation of each one. For every
endpoint ask:

- What inputs can the attacker control?
- Is authentication, authorization, signature verification, tenant isolation, or
  a business-state check bypassed or missing?
- IDOR: can a user reach another user's, tenant's, or service's resource by a
  supplied id?
- Do privileged operations (payment, signing, approval, state change) allow state
  bypass or replay (no nonce / time window)?
- Mass assignment: is a user-controlled body bound wholesale into a model?
- Signature: is a caller-supplied key trusted as the trust anchor?

Record the API inventory in `api/` (one file per module: route + auth method +
review status ✅/⚠️/❌). Record architecture understanding and high-risk paths in
`analysis/`.

## Scope

Report only HIGH / CRITICAL, exploitable, high-confidence issues. **Do not report**
(regardless of severity): dependency CVEs, style or best-practice notes,
speculative issues you cannot tie to a concrete exploit, and risks that only
matter if production config is leaked.

## Recording an issue

Write one `issues/<name>.md` per confirmed issue. Do not write an issue you cannot
confirm with high confidence. Each must have:

```markdown
# <title>

- Risk: HIGH | CRITICAL
- Type: IDOR | auth bypass | signature flaw | business logic | ...
- Endpoint: `<METHOD> <path>`

## Analysis
(cite exact file paths and line numbers)

## Attack path
(end-to-end, actionable steps)

## PoC
(a curl command or script that actually triggers it)

## Verification
(result of actually running the PoC in a sandbox / dev environment)

## Fix
```

## PoC verification (human in the loop)

Confirm each issue by running the PoC against a sandbox / dev environment. When
you need something only the operator has, stop and ask:

- an auth cookie or token,
- an MFA step,
- specific test data or an account.

Never run a PoC against production, and never use real credentials or perform a
destructive action without the operator's explicit go-ahead.

## Iteration

Each round, read the workspace history first and do not repeat finished work.
Process leftover TODOs; otherwise pick an unreviewed (❌) or to-deepen (⚠️)
endpoint from the API inventory. When every endpoint is ✅ and there are no TODOs,
report the review complete.

## On finish

Append a row to the audit history in `security-review-memory.md`, and ask the
operator which findings were false positives. Record those under "Confirmed false
positives" so future rounds skip them.
