# Repo Security Review — Agent Methodology

The `review repo` path: a whole-repository security audit, run by an interactive
coding agent (Claude Code, Codex, etc.), not a one-shot LLM call. It maps the
attack surface, traces inputs to sinks across files, verifies issues with a real
PoC, and iterates over multiple rounds with a persistent memory. One round is
roughly 30 minutes; run as many rounds as needed.

Target repository: the directory you were given.
Workspace: `<workspace>/<project>/` (created for you), holding `entrypoints/`,
`issues/`, `analysis/`, and `security-review-memory.md`.

---

## On start (do this first)

1. Read `security-review-memory.md` in the workspace if it exists:
   - skip every pattern under "Confirmed false positives";
   - do not re-report anything under "Fixed";
   - weight the files under "High-risk areas" more heavily.
2. Read `entrypoints/_entrypoints.md` (seeded for you from a deterministic AST
   scan) as a *starting* map of the attack surface. It lists HTTP routes and CLI
   commands only, a subset, not the whole surface (see "Map the attack surface").
3. Read `_stack.md` (seeded): the detected languages and frameworks and review
   notes for them, so you know where this stack's entrypoints, sinks, and auth
   checks live. If it matched nothing, lean on your own knowledge of the stack.
4. Read the relevant rule files under the shipped `rules/` for the target's stack
   (sql-injection, idor, ssrf, authentication-jwt, insecure-deserialization, ...).

## Map the attack surface

The seeded inventory lists HTTP routes and CLI commands only. Before analysing,
complete the surface: untrusted input enters at more than HTTP. Enumerate every
source the attacker can influence and add it to `entrypoints/`:

- HTTP routes, GraphQL resolvers, gRPC / RPC handlers, WebSocket handlers;
- CLI commands, scheduled jobs / cron, queue and topic consumers, webhooks and
  third-party callbacks;
- deserialization points (pickle, yaml.load, marshal), file and document parsers
  (XML / XXE, YAML, CSV, zip, image / office), template rendering of user input;
- file uploads, archive extraction, and any filesystem path built from user input;
- headers, cookies, environment, and config read as trusted, and inbound
  inter-service calls.

`pickle.loads(cookie)` and `yaml.load(upload)` are entrypoints just as much as a
route is. Record the inventory in `entrypoints/` (one file per module: source +
auth method + review status ✅/⚠️/❌).

## Analyse each source

Read the implementation reachable from each source. For every one ask:

- What inputs can the attacker control?
- Is authentication, authorization, signature verification, tenant isolation, or
  a business-state check bypassed or missing?
- IDOR: can a user reach another user's, tenant's, or service's resource by a
  supplied id?
- Do privileged operations (payment, signing, approval, state change) allow state
  bypass or replay (no nonce / time window)?
- Mass assignment: is a user-controlled body bound wholesale into a model?
- Signature: is a caller-supplied key trusted as the trust anchor?

## Trace attack paths (the core work)

A whole-repo review earns its keep by reasoning *across files*: a flaw is usually
a source in one file reaching a dangerous sink in another, past a control defined
in a third (a route that trusts a helper which skips signature checks; an id that
reaches a query with no ownership check). For each promising source, trace the
path and record it in `analysis/`:

- **Source**: the entrypoint and the attacker-controlled value.
- **Sink**: the dangerous operation it reaches (query, shell, file path, fetch,
  deserialize, template, redirect), with `file:line`.
- **Controls on the path**: every auth / authz / validation / sanitization /
  signature / tenant check between source and sink, and crucially which are
  missing or bypassable.

The vulnerability is a path with a reachable sink and no adequate control. Record
the system's trust boundaries and auth/authz model in `analysis/` once, so every
trace can refer to it instead of restating it.

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
- Source: `<METHOD> <path>` or the non-HTTP entrypoint (queue, deserializer, ...)

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
source from the inventory. When every source is ✅ and there are no TODOs,
report the review complete.

## On finish

Append a row to the audit history in `security-review-memory.md`, and ask the
operator which findings were false positives. Record those under "Confirmed false
positives" so future rounds skip them.
