# Repo Security Review: Agent Methodology

The `review repo` path: a whole-repo security audit run by an interactive coding
agent such as Claude Code or Codex, not a one-shot LLM call. The agent maps the
attack surface, traces inputs to sinks across files, and proves each issue with a
real PoC, over as many rounds as it takes.

You already know security. This methodology is not a tutorial on vulnerability
classes, it is a set of forcing functions against the ways an agent under-performs
a review: stopping shallow, clearing a finding the moment it sees a control,
detecting a real issue then dropping it at triage, and interrupting the operator.
Each step below names the shortcut it blocks.

It rests on three pillars:

- **Coverage**, find every real issue. A complete surface inventory, a trace from
  each source to its sink, a challenge of every control, and rounds that run until
  nothing new appears. Shallowness is made visible in the workspace so it cannot
  pass as a clean result.
- **Truth**, report only what is real. A finding is a hypothesis until it survives
  refutation. You usually cannot run a PoC, so the arbiter is a fresh skeptical
  pass that tries to disprove the finding by reading the code, not your confidence
  in it. A reproduced PoC is the strongest evidence when a runtime is available,
  but the static refutation is the gate that always runs. Every finding carries a
  status.
- **Autonomy**, do not burden the operator. The review runs end to end on its own.
  The one irreducible human dependency, the credentials and go-ahead to run a PoC
  safely, is deferred to a separate phase, never asked for mid-run.

So the work splits into two phases. Phase 1 is an autonomous review that traces,
refutes its own candidate findings, and produces confirmed and blocked findings
plus a list of what verification needs. Phase 2 is an operator-driven re-run that
settles the blocked findings, the ones whose verdict needs a runtime fact, once the
operator can supply it.

Target repository: the directory you were given.
Workspace: `<workspace>/<project>/`, created for you, holding `entrypoints/`,
`issues/`, `pocs/`, `analysis/`, and `MEMORY.md`.

---

## On Start

1. Read `MEMORY.md` in the workspace if it exists:
   - skip every pattern under "Confirmed false positives".
   - do not re-report anything under "Fixed".
   - weight the files under "High-risk areas" more heavily.
2. Read `entrypoints/_entrypoints.md`, the seeded list of files the detected stack
   flags as likely to define entrypoints. It is a starting subset, not the whole
   surface, see "Map the Attack Surface".
3. Read `_stack.md`, the seeded languages, frameworks, and protocols plus review
   notes, so you know where this stack's entrypoints and sinks live and which
   protocol checks apply, such as the OAuth checklist. If it matched nothing, lean
   on your own knowledge of the stack.
4. Read the relevant vulnerability files under the shipped `vulnerabilities/` for
   the target's stack, such as sql-injection, idor, ssrf, jwt-validation, or
   insecure-deserialization.
5. Read `analysis/_trace_targets.md`, the seeded downstream logic-layer files such
   as managers and dao to trace into, and `analysis/_rounds.md`, the round ledger
   you must keep.
6. Read `_false_positive_traps.md`, the recurring patterns that make a static read
   call a finding real when it is not. You apply these before reporting, see
   "Refute Before Reporting".

---

# Phase 1: The Review

Run Phase 1 unattended to the Completeness Gate. It produces confirmed and blocked
findings and a verification-needs list, and never pauses to ask the operator
anything, see "Rounds and the Completeness Gate".

## Map the Attack Surface

*Coverage. Blocks reviewing only the endpoints that are obvious.*

The seeded `entrypoints/_entrypoints.md` is a starting point, not the whole
surface. Before any per-source analysis, build a COMPLETE inventory: open every
flagged file, read its routes and handlers, and enumerate every source an attacker
can influence, including the ones no scan finds. Untrusted input enters at more
than HTTP:

- HTTP routes, GraphQL resolvers, gRPC / RPC handlers, WebSocket handlers.
- CLI commands, scheduled jobs / cron, queue and topic consumers, webhooks and
  third-party callbacks.
- deserialization points such as pickle, yaml.load, or marshal, file and document
  parsers for XML / XXE, YAML, CSV, zip, image / office, and template rendering of
  user input.
- file uploads, archive extraction, and any filesystem path built from user input.
- headers, cookies, environment, and config read as trusted, and inbound
  inter-service calls.

`pickle.loads(cookie)` and `yaml.load(upload)` are entrypoints just as much as a
route is. Record the full inventory in `entrypoints/`, one file per module, each
listing the source, the auth method, and a review status ✅/⚠️/❌. Do not begin
per-source analysis until the inventory covers every endpoint, since an endpoint
you never list is one you never review. This step most decides whether the review
finds the deep issues.

## Trace Each Source to Its Sink

*Coverage. Blocks stopping at the view instead of following the call into the logic
layer where the flaw lives.*

A whole-repo review earns its keep by reasoning across files. A flaw is usually a
source in one file reaching a dangerous sink in another, past a control defined in
a third, such as a route that trusts a helper which skips a signature check, or an
id that reaches a query with no ownership check. The flaw usually lives below the
entrypoint, in a manager, a controller, a dao, or a service, not in the view. The
seeded `analysis/_trace_targets.md` lists those downstream layers.

For each source, follow the calls out of the entrypoint into those layers to the
real sink, asking as you go:

- What inputs can the attacker control?
- Is authentication, authorization, signature verification, tenant isolation, or a
  business-state check missing or bypassable?
- IDOR: can a caller reach another user's, tenant's, or service's resource by a
  supplied id, however the id arrives?
- Does a privileged operation such as payment, signing, approval, or a state change
  allow replay or state bypass with no nonce or time window?
- Mass assignment: is a user-controlled body bound wholesale into a model?
- Signature: is a caller-supplied key trusted as the trust anchor?

Record each path in `analysis/`:

- **Source**: the entrypoint and the attacker-controlled value.
- **Sink**: the dangerous operation it reaches such as a query, shell, file path,
  fetch, deserialize, template, or redirect, with `file:line`.
- **Controls on the path**: every auth, authz, validation, sanitization, signature,
  or tenant check between source and sink, and which are missing or bypassable.

The vulnerability is a path with a reachable sink and no adequate control. Record
the system's trust boundaries and auth model in `analysis/` once, so every trace
refers to it instead of restating it. An entrypoint is not done until its path is
traced to a sink or explicitly cleared, since stopping at the view is what hides
the deep flaw, such as a missing lock in a dao or a skipped expiry check in a
manager.

## The Authorization Model Pass

*Coverage. Missing authorization and IDOR are not local to one function, so they
get their own pass.*

This pass is language and framework agnostic. The access gate looks different per
stack, a decorator, a middleware, a permission class, a filter, a guard, or an
annotation, but every protected endpoint must authenticate the caller and authorize
the specific resource.

First map how this codebase enforces access control, then record on each inventory
entry which gate it applies and which identity and resource it checks. Then hunt
three shapes:

- A peer that dropped a check. Compare sibling endpoints such as a v1 and a v2, a
  batch and a single, or an admin and a public variant. When one applies an
  ownership or permission check a sibling omits, the sibling is a likely flaw.
- IDOR. An endpoint acts on a resource named by a client-supplied id with no owner
  or tenant check.
- An unauthenticated privileged path. A state-changing or sensitive endpoint is
  reachable without the gate its peers require.

## Challenge Every Control

*Coverage. Blocks clearing a path the moment a control is present, without asking
whether it holds.*

A control being present is not the same as the control holding. For every control
you find on a path, do not clear on presence. Challenge it on four axes:

- **Replay**. A signed or authenticated privileged request is replayable unless the
  control BOTH consumes a one-time nonce AND enforces a freshness window such as a
  timestamp or short expiry. That the caller is authenticated, that the scheme
  fails closed, or that a TOTP is single-use is orthogonal to replay. Capture one
  valid request and ask: can the exact same bytes be sent again and accepted?
- **Concurrency and state**. A check-then-act is bypassable under concurrent
  requests unless a lock is held across the act, even when the single-request path
  looks single-use. A redeem, a balance debit, or a status transition that reads
  then writes without a row lock double-spends under a race.
- **Sibling coverage**. A gate on one endpoint does not cover its siblings. When you
  find a missing-authorization or IDOR pattern, enumerate every endpoint behind the
  same controller or gate and carry the highest-impact instance, not the first one
  you saw.
- **Trusted-source assumptions**. A value is not safe just because a caller you
  treat as trusted set it. If that caller is a distinct tenant or service, the value
  is still attacker-influenced. A self-set `callback_url` that flows into a
  server-side fetch is SSRF or a worker-blocking DoS unless there is an allowlist.

A control that passes one axis can fail another, so run all four before you mark a
path cleared, and record which axis you checked.

**The control may live in a library.** The authentication, the signature or replay
check, the permission test is often implemented in a library the endpoint calls,
internal or third-party. You cannot judge the endpoint from first-party code alone.
Follow into the specific function the path depends on, read it where it is installed
or vendored, and verify it actually enforces the control, such as a signature check
that also binds a nonce or a timestamp window. This is not auditing the library for
its own bugs, it is confirming the control your endpoint relies on holds here.

**Clear per endpoint, never per class.** Do not clear a group with one statement
such as "the write paths are all scoped" or "the connection logins are sound". A
check present on one sibling can be commented out, skipped, or absent on another,
and a class-wide clear makes that invisible. Read the actual gate in each endpoint's
own code. A commented-out or skipped check is a finding, not a clear.

**Apply a trust-boundary assumption consistently.** Once you adopt an assumption
about a boundary to grade one finding, such as treating a service or tenant as
distinct and mutually distrusting, grade every finding on that same boundary the
same way. If that assumption makes a self-set `callback_url` a HIGH SSRF, then a
cross-service read of another service's data on the same boundary is a HIGH IDOR,
not a below-bar note.

## What to Report

*Truth. Blocks detecting a real issue then dropping it with a conservative severity
estimate.*

Report only exploitable, high-confidence issues at HIGH or CRITICAL. Do NOT report,
regardless of severity: dependency CVEs, style or best-practice notes, speculative
issues with no concrete exploit, and risks that only matter if production config is
leaked. A control a library fails to enforce for a reachable first-party entrypoint
is not a dependency CVE, it is this app's exploitable exposure, so it is in scope.

Rate by impact, not by how local the bug looks. A control that protects money,
signing, approval, authentication, identity, or tenant isolation is HIGH or CRITICAL
when it can be defeated, even when the defeat is a single missing line and even when
the fix lands in a library. An authorization code or token with no expiry, a
replayable signed request, a binding or ownership check that is commented out, and a
cross-tenant read or write are HIGH, not MEDIUM. Do not let a conservative severity
estimate drop a real exploitable issue. When you have a concrete exploit but are
unsure it clears the bar, report it with your severity reasoning rather than parking
it below. The bar excludes issues with no concrete exploit, not exploitable issues
you are unsure how to grade.

## Recording a Finding

*Truth. A finding is a hypothesis until it survives refutation, so every finding
carries a runnable PoC and a status.*

Write one `issues/<name>.md` write-up and save its PoC as a real runnable file
`pocs/<name>.<ext>` with the same `<name>`, a script or an `.http` file, not a
sketch in prose and not a `.md`. Keep the two directories separate. If you cannot
write a concrete runnable PoC, the finding is most likely a guess, so do not report
it.

```markdown
# <title>

- Risk: HIGH | CRITICAL
- Type: IDOR | auth bypass | signature flaw | business logic | ...
- Source: `<METHOD> <path>` or the non-HTTP entrypoint (queue, deserializer, ...)
- Status: confirmed | blocked | refuted
- Needs: (only when Status is blocked) the exact input a follow-up run must supply

## Analysis
(cite exact file paths and line numbers)

## Attack Path
(end-to-end, actionable steps)

## PoC
(the path to `pocs/<name>.<ext>` and how to run it)

## Verification
(the refutation attempt and its outcome, plus any PoC output, or the exact blocker)

## Fix
```

The `Status` is the spine of the review and the contract a re-run follows. Because
a PoC usually cannot run, the status is set by the refutation in "Refute Before
Reporting", not by execution:

- **confirmed**: the finding survived refutation, a fresh skeptical read tried to
  disprove it and could not. These are reported. A reproduced PoC, when a runtime
  is available, makes a confirmed finding stronger but is not required to confirm.
- **blocked**: it survived refutation, but settling it for sure needs a runtime
  fact you cannot read from the code, a credential, a deploy-config value, or live
  behavior. Record the exact need in `Needs:`, grade it on the conservative
  assumption, and keep going. This is the worklist for Phase 2.
- **refuted**: the refutation found a controlling fact that makes the code safe, or
  a PoC ran and did not trigger. Terminal. Move it under "Confirmed false
  positives" in `MEMORY.md` and do not report it.

Running a PoC against a real environment, with real credentials, or any destructive
action belongs to Phase 2, never here. In Phase 1 you may run a PoC only when it
needs no operator input.

## Refute Before Reporting

*Truth. Blocks reporting a confident misread. This is the gate that always runs,
since a PoC usually cannot.*

A candidate finding is the offense's claim that a control is missing or bypassable.
Before you set its status, switch sides and try to prove it is a false positive. Do
this for every candidate, from a fresh read, not as a rubber stamp on your own work:

1. **Name the controlling fact.** State the one thing that, if true, makes the code
   safe: the lock is actually held, the value is server-set not attacker-set, the
   check lives in a decorator or base class, the input never reaches the sink, the
   two sides share a trust domain. Then read that exact code and settle it.
2. **Run the trap checklist.** Check the finding against every pattern in
   `_false_positive_traps.md`. These are the recurring ways a static read calls a
   finding real when it is not, such as a lock held by a `SELECT ... FOR UPDATE`
   whose result was discarded, or an id that comes from the session rather than the
   request.
3. **Decide and record.** If the controlling fact holds, mark the finding
   **refuted**, record the pattern under "Confirmed false positives" in `MEMORY.md`,
   and do not report it. If you read the code and the control genuinely is absent or
   bypassable, mark it **confirmed**. If the verdict turns on a runtime fact you
   cannot read, mark it **blocked** with the exact `Needs:`. Write the refutation
   attempt into the issue's `Verification` section so a reader sees it was
   challenged, not asserted.

Default to refuted when the controlling fact holds. Survive the refutation, do not
explain it away. A finding you cannot defend against a fresh skeptical read is a
guess, and the trap that recurs most is calling a control absent without reading
where it actually lives.

## Rounds and the Completeness Gate

*Coverage and Autonomy. Blocks one round and done, and blocks pausing to ask the
operator.*

Each round, read the workspace history first and do not repeat finished work. Pick
an unreviewed ❌ or to-deepen ⚠️ source, trace it to its sink, challenge its
controls, record any finding, and log the round in `analysis/_rounds.md`. One round
is roughly 30 minutes and rarely finds the deep cross-file and stateful bugs. The
hard classes such as authorization, replay, and broken business state usually appear
only after several rounds, so keep going.

**Run unattended.** Do not pause between rounds to ask whether to continue, do not
stop early because a round was productive, and do not stop because a PoC is blocked
or because you lack an operator input to grade a finding. When you lack an input,
such as how broadly a credential is distributed or whether a service is trusted,
proceed on the conservative assumption that keeps the finding exploitable, grade on
it, and note the assumption. Gather every operator input you would want, the blocked
PoC credentials, the trust-boundary questions, and the candidate false positives,
into the verification-needs list for "On Finish". Do not ask for any of it mid-run.

**The gate.** Do not report the review complete until all of these hold. A short run
with most entrypoints still ❌ is incomplete, not clean, and reporting it as clean is
the failure this gate prevents.

- Every entrypoint in the inventory is resolved to ✅, none left ❌.
- Each entrypoint's path is traced to a real sink or explicitly cleared, not stopped
  at the view.
- The Authorization Model pass ran.
- Every control on a cleared path was challenged on all four axes, see "Challenge
  Every Control", not cleared on presence.
- Every reported finding survived refutation, see "Refute Before Reporting", and
  its `Status` was set from that read, not asserted.
- `analysis/_rounds.md` shows two consecutive rounds that added no new source, no
  new traced path, and no new issue.

Resolving an entrypoint to ✅ means you read the code on its path to the sink and
either filed a finding or cleared it on a specific reason that cites the code. A
blanket dismissal, a park below the bar, or a class-wide clear does not resolve an
entrypoint. The goal is every real issue found, not every entrypoint marked done. If
any item fails, run another round, and state which items pass when you report.

## On Finish

Phase 1 runs to completion on its own and then stops, without pausing to ask the
operator anything. End it with a single report:

- **Confirmed**, the `Status: confirmed` findings that survived refutation. A
  reproduced PoC strengthens them when a runtime was available, but is not required.
- **Blocked**, the `Status: blocked` findings that survived refutation but whose
  verdict needs a runtime fact, each graded on its conservative assumption with its
  exact `Needs:`.
- **Verification needs**, one consolidated list gathered from the blocked findings'
  `Needs:` lines, the credentials and test data per PoC, the trust-boundary
  questions, and the candidate false positives to rule out. This is a section of the
  report, not a question. Do not wait on it.

Append a row to the audit history in `MEMORY.md`, then stop.

---

# Phase 2: Verification Re-run

*Truth and Autonomy. Where blocked hypotheses become confirmed or refuted, and the
only place a PoC actually executes.*

When the operator returns with the credentials and answers, they record any accepted
false positives under "Confirmed false positives" in `MEMORY.md`, then start a
re-run over the same workspace, not a `--fresh` one, so every issue keeps its
status. This is not a fresh review, it is a sweep driven by `Status`:

- Act only on findings marked **blocked**. Skip every **confirmed** and **refuted**
  one, and skip anything under "Confirmed false positives" in `MEMORY.md`. They are
  terminal, do not re-investigate them.
- For each blocked finding, settle it with the now-available fact, run its PoC, or
  check the deploy-config or trust-boundary answer. Rewrite the status in place,
  **confirmed** if it holds, **refuted** if it does not, and record a refuted one
  under "Confirmed false positives" in `MEMORY.md`.
- A blocked finding whose input still did not arrive stays **blocked** for the next
  re-run.

Never run a PoC against production, and never use real credentials or perform a
destructive action without the operator's explicit go-ahead. The lifecycle is a
resumable pipeline, `blocked -> confirmed` or `blocked -> refuted`, so a re-run only
spends effort on the unverified findings and never redoes a settled one.
