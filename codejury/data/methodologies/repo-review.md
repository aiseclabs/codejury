# Repo Security Review: Agent Methodology

The `review repo` path: a whole-repo security audit, run by an interactive
coding agent such as Claude Code or Codex, not a one-shot LLM call. It maps the
attack surface, traces inputs to sinks across files, verifies issues with a real
PoC, and iterates over multiple rounds with a persistent memory. One round is
roughly 30 minutes. Run as many rounds as needed.

Target repository: the directory you were given.
Workspace: `<workspace>/<project>/`, created for you, holding `entrypoints/`,
`issues/`, `analysis/`, and `MEMORY.md`.

---

## On Start

1. Read `MEMORY.md` in the workspace if it exists:
   - skip every pattern under "Confirmed false positives".
   - do not re-report anything under "Fixed".
   - weight the files under "High-risk areas" more heavily.
2. Read `entrypoints/_entrypoints.md`, the seeded list of files the detected stack
   flags as likely to define entrypoints. Open them to find the actual
   entrypoints. It is a *starting* subset, not the whole surface. See "Map the
   attack surface".
3. Read `_stack.md`, the seeded detected languages, frameworks, and protocols plus
   review notes for them, so you know where this stack's entrypoints and sinks
   live and which protocol checks apply, for example the OAuth checklist. If it
   matched nothing, lean on your own knowledge of the stack.
4. Read the relevant vulnerability files under the shipped `vulnerabilities/` for
   the target's stack such as sql-injection, idor, ssrf, jwt-validation, or
   insecure-deserialization.
5. Read `analysis/_trace_targets.md`, the seeded downstream logic-layer files such
   as managers and dao to trace into, and `analysis/_rounds.md`, the round ledger
   you must keep. See "Trace Attack Paths" and "Completeness Gate".

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

## Authorization Model

The missing-authorization and IDOR classes are not local to one function, so they
need their own pass. This step is language and framework agnostic. The access
gate looks different per stack, a decorator, a middleware, a permission class, a
filter, a guard, or an annotation, but every protected endpoint must authenticate
the caller and authorize the specific resource.

First map how this codebase enforces access control, then record on each
inventory entry which gate it applies and which identity and resource it checks.
Then hunt three shapes:

- A peer that dropped a check. Compare sibling endpoints such as a v1 and a v2, a
  batch and a single, or an admin and a public variant. When one applies an
  ownership or permission check that a sibling omits, the sibling is a likely
  flaw.
- IDOR. An endpoint acts on a resource named by a client-supplied id with no
  owner or tenant check, however the id arrives.
- An unauthenticated privileged path. A state-changing or sensitive endpoint is
  reachable without the gate its peers require.

## Trace Attack Paths, the Core Work

A whole-repo review earns its keep by reasoning *across files*: a flaw is usually
a source in one file reaching a dangerous sink in another, past a control defined
in a third, for example a route that trusts a helper which skips signature checks, or an id that
reaches a query with no ownership check. The flaw usually lives below the
entrypoint, in a manager, a controller, a dao, or a service, not in the view. The
seeded `analysis/_trace_targets.md` lists those downstream logic-layer files. For
each promising source, follow the calls out of the entrypoint into those layers
to the real sink, and record the path in `analysis/`:

- **Source**: the entrypoint and the attacker-controlled value.
- **Sink**: the dangerous operation it reaches such as a query, shell, file path, fetch,
  deserialize, template, or redirect, with `file:line`.
- **Controls on the path**: every auth / authz / validation / sanitization /
  signature / tenant check between source and sink, and crucially which are
  missing or bypassable.

The vulnerability is a path with a reachable sink and no adequate control. Record
the system's trust boundaries and auth/authz model in `analysis/` once, so every
trace can refer to it instead of restating it. An entrypoint is not done until its
path is traced through the downstream layers to a sink or cleared, since stopping
at the view is what hides the deep flaw, for example the missing lock in a dao or
the skipped expiry check in a manager.

## Controls That Live in a Library

An entrypoint's security control is often not in the first-party code at all: the
authentication, the signature or replay check, the permission test is implemented
in a library the endpoint calls. You cannot judge whether the endpoint is
exploitable from the first-party code alone, because the control that would stop
the attack lives in the library.

So when a traced path relies on a control a library provides, follow into that
library's relevant function and verify it actually enforces the control, for
example that a signature check also binds a nonce or a timestamp window, or that
an auth helper truly validates the caller. Read the specific function the path
depends on, not the whole library, and read it where it is installed or vendored.

This is about this app's exposure, so it applies to any library, internal or
third-party. It is not auditing the library for its own bugs, which belongs to
that library's own review. It is confirming that the control your endpoint relies
on holds here.

## Scope

Report only HIGH / CRITICAL, exploitable, high-confidence issues. **Do not report**
regardless of severity, dependency CVEs, style or best-practice notes,
speculative issues you cannot tie to a concrete exploit, and risks that only
matter if production config is leaked. A control that a library fails to enforce
for a reachable first-party entrypoint is not a dependency CVE, it is this app's
exploitable exposure, so it is in scope. See "Controls That Live in a Library".

## Recording an Issue

Write one `issues/<name>.md` per issue, the write-up only, and save its PoC as a
real runnable file `pocs/<name>.<ext>` with the **same `<name>`** so the two pair
one to one, a script or an `.http` file, not a sketch in prose and not a `.md`.
Keep `issues/` write-ups and `pocs/` scripts in their own directories, do not mix
them. If you cannot write a concrete runnable PoC, the finding is most likely a
false positive, so do not report it. Each issue file must have:

```markdown
# <title>

- Risk: HIGH | CRITICAL
- Type: IDOR | auth bypass | signature flaw | business logic | ...
- Source: `<METHOD> <path>` or the non-HTTP entrypoint (queue, deserializer, ...)
- Verification: reproduced | blocked, needs <what> | not run

## Analysis
(cite exact file paths and line numbers)

## Attack Path
(end-to-end, actionable steps)

## PoC
(the path to `pocs/<name>.<ext>` and how to run it)

## Verification
(the actual output of running the PoC, or the exact blocker)

## Fix
```

## PoC Verification, the False-Positive Gate

A finding is a hypothesis until a PoC proves it. The tool, and you, can be
confident and still wrong, so the PoC is what separates a real vulnerability from
a plausible misread. Confirm each issue by running its PoC against a sandbox or
dev environment, and gate reporting on the result:

- **Reproduced**: the PoC ran and triggered the issue. Only these are reported as
  confirmed HIGH / CRITICAL.
- **Blocked**: the PoC is written and correct but you need something only the
  operator has, so stop and ask, for an auth cookie or token, an MFA step, or
  specific test data or an account. Report these separately as suspected and
  needing verification, with the exact blocker, never mixed into the confirmed
  set.
- **Not run with no concrete PoC**: do not report. It is a guess.

Never run a PoC against production, and never use real credentials or perform a
destructive action without the operator's explicit go-ahead.

## Iteration

Each round, read the workspace history first and do not repeat finished work.
Process leftover TODOs, otherwise pick an unreviewed ❌ or to-deepen ⚠️ source
from the inventory, trace it through the downstream layers, and log the round in
`analysis/_rounds.md`. One round rarely finds the deep cross-file and stateful
bugs. The hard classes such as authorization, replay, and broken business state
usually appear only after several rounds, so keep going.

## Completeness Gate

Do not report the review complete until all of the following hold. A short run
with most entrypoints still ❌ is an incomplete review, not a clean one, and
reporting it as clean is the failure this gate exists to prevent.

- Every entrypoint in the inventory is resolved to ✅, none left ❌.
- Each entrypoint's path is traced through the downstream layers in
  `analysis/_trace_targets.md` to a real sink or explicitly cleared, not stopped
  at the view.
- The Authorization Model pass ran: the access gate is mapped, sibling endpoints
  compared, and IDOR and unauthenticated privileged paths checked.
- `analysis/_rounds.md` shows two consecutive rounds that added no new source, no
  new traced path, and no new issue.

If any item fails, run another round. State which items pass when you report.

## On Finish

Report the confirmed findings, the ones with a reproduced PoC, separately from
the suspected ones still blocked on verification, so the two are never conflated.
Append a row to the audit history in `MEMORY.md`, and ask the
operator which findings were false positives. Record those under "Confirmed false
positives" so future rounds skip them.
