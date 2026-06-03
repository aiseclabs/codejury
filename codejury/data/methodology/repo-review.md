# Repo Security Review: Agent Methodology

The `review repo` path: a whole-repository security audit, run by an interactive
coding agent such as Claude Code or Codex, not a one-shot LLM call. It maps the
attack surface, traces inputs to sinks across files, verifies issues with a real
PoC, and iterates over multiple rounds with a persistent memory. One round is
roughly 30 minutes. Run as many rounds as needed.

Target repository: the directory you were given.
Workspace: `<workspace>/<project>/`, created for you, holding `entrypoints/`,
`issues/`, `analysis/`, and `security-review-memory.md`.

---

## On Start

1. Read `security-review-memory.md` in the workspace if it exists:
   - skip every pattern under "Confirmed false positives".
   - do not re-report anything under "Fixed".
   - weight the files under "High-risk areas" more heavily.
2. Read `entrypoints/_entrypoints.md`, the seeded list of files the detected stack
   flags as likely to define entrypoints. Open them to find the actual
   entrypoints. It is a *starting* subset, not the whole surface. See "Map the
   attack surface".
3. Read `_stack.md`, the seeded detected languages, frameworks, and topics plus
   review notes for them, so you know where this stack's entrypoints and sinks
   live and which protocol checks apply, for example the OAuth checklist. If it
   matched nothing, lean on your own knowledge of the stack.
4. Read the relevant rule files under the shipped `rules/` for the target's stack
   such as sql-injection, idor, ssrf, authentication-jwt, or insecure-deserialization.

## Map the Attack Surface

The seeded `entrypoints/_entrypoints.md` flags files that likely define
entrypoints. It is a starting point, not the whole surface. Before any per-source
analysis, build a COMPLETE inventory: open every flagged file, read its routes
and handlers, and enumerate every source the attacker can influence, including
the ones no scan finds. Untrusted input enters at more than HTTP:

- HTTP routes, GraphQL resolvers, gRPC / RPC handlers, WebSocket handlers.
- CLI commands, scheduled jobs / cron, queue and topic consumers, webhooks and
  third-party callbacks.
- deserialization points such as pickle, yaml.load, or marshal, file and document parsers
  for XML / XXE, YAML, CSV, zip, image / office, and template rendering of user input.
- file uploads, archive extraction, and any filesystem path built from user input.
- headers, cookies, environment, and config read as trusted, and inbound
  inter-service calls.

`pickle.loads(cookie)` and `yaml.load(upload)` are entrypoints just as much as a
route is. Record the full inventory in `entrypoints/`, one file per module, each
listing the source, the auth method, and a review status ✅/⚠️/❌. Do not begin
per-source analysis until the inventory covers every endpoint, since an endpoint
you never list is one you never review. This single step is what most decides
whether the review finds the deep issues.

## Analyse Each Source

Read the implementation reachable from each source. For every one ask:

- What inputs can the attacker control?
- Is authentication, authorization, signature verification, tenant isolation, or
  a business-state check bypassed or missing?
- IDOR: can a user reach another user's, tenant's, or service's resource by a
  supplied id?
- Do privileged operations such as payment, signing, approval, or state change allow state
  bypass or replay with no nonce or time window?
- Mass assignment: is a user-controlled body bound wholesale into a model?
- Signature: is a caller-supplied key trusted as the trust anchor?

## Trace Attack Paths, the Core Work

A whole-repo review earns its keep by reasoning *across files*: a flaw is usually
a source in one file reaching a dangerous sink in another, past a control defined
in a third, for example a route that trusts a helper which skips signature checks, or an id that
reaches a query with no ownership check. For each promising source, trace the
path and record it in `analysis/`:

- **Source**: the entrypoint and the attacker-controlled value.
- **Sink**: the dangerous operation it reaches such as a query, shell, file path, fetch,
  deserialize, template, or redirect, with `file:line`.
- **Controls on the path**: every auth / authz / validation / sanitization /
  signature / tenant check between source and sink, and crucially which are
  missing or bypassable.

The vulnerability is a path with a reachable sink and no adequate control. Record
the system's trust boundaries and auth/authz model in `analysis/` once, so every
trace can refer to it instead of restating it.

## Scope

Report only HIGH / CRITICAL, exploitable, high-confidence issues. **Do not report**
regardless of severity, dependency CVEs, style or best-practice notes,
speculative issues you cannot tie to a concrete exploit, and risks that only
matter if production config is leaked.

## Recording an Issue

Write one `issues/<name>.md` per confirmed issue. Do not write an issue you cannot
confirm with high confidence. Each must have:

```markdown
# <title>

- Risk: HIGH | CRITICAL
- Type: IDOR | auth bypass | signature flaw | business logic | ...
- Source: `<METHOD> <path>` or the non-HTTP entrypoint (queue, deserializer, ...)

## Analysis
(cite exact file paths and line numbers)

## Attack Path
(end-to-end, actionable steps)

## PoC
(a curl command or script that actually triggers it)

## Verification
(result of actually running the PoC in a sandbox / dev environment)

## Fix
```

## PoC Verification, Human in the Loop

Confirm each issue by running the PoC against a sandbox / dev environment. When
you need something only the operator has, stop and ask:

- an auth cookie or token,
- an MFA step,
- specific test data or an account.

Never run a PoC against production, and never use real credentials or perform a
destructive action without the operator's explicit go-ahead.

## Iteration

Each round, read the workspace history first and do not repeat finished work.
Process leftover TODOs, otherwise pick an unreviewed ❌ or to-deepen ⚠️ source
from the inventory. One round rarely finds the deep cross-file and stateful bugs,
so keep going until two consecutive rounds surface nothing new, then report the
review complete. The hard classes such as authorization, replay, and broken
business state usually appear only after several rounds.

## On Finish

Append a row to the audit history in `security-review-memory.md`, and ask the
operator which findings were false positives. Record those under "Confirmed false
positives" so future rounds skip them.
