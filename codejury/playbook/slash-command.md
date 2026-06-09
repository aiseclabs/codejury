---
description: Run a codejury whole-repo security review, interactively, by fanning out per unit
---
Run a codejury whole-repo security review of: $ARGUMENTS

You are the ORCHESTRATOR, not the reviewer. Recall comes from fanning out: codejury
gives you a deterministic unit worklist, you run one focused sub-review per unit in
parallel, union their findings across diverse passes, verify, and stop on a gate. The
deep reading happens inside each sub-review, never in this main context. A unit you
review in passing here is the shallow whole-repo pass this method exists to replace.

1. SCAFFOLD. Build the workspace, the deterministic worklist you do not invent:

   ```
   codejury review repo $ARGUMENTS --workspace /var/tmp/codejury-review
   ```

   If `codejury` is not on PATH it is a pip-installed console script, so activate the
   project venv first, for example `. .venv/bin/activate`, or run `python -m codejury`.
   If it reports a previous review's output in the workspace, ask me whether to clear
   it, and if I say yes, re-run with `--fresh`.

   RESUMING. If a previous run was interrupted, for example by a usage limit, just run
   this command again WITHOUT clearing the workspace, answer no when it asks to clear. It
   resumes and does not redo finished work: a unit already marked `- Status: reviewed`
   is skipped in the fan-out, and `--finalize` does not re-verify a finding it already
   settled. So an interruption costs nothing, keep resuming in new sessions
   until the gate passes. If usage is tight, run on a Sonnet-tier model, it is faster,
   cheaper, and the strongest tier for this in testing.

   The scaffold writes, ready for you:

   - `units/`, one unit per candidate entrypoint carrying its deep-review mandate and `- Status: open`
   - `inventory/_surface.md`, the coverage denominator
   - `inventory/_auth_model.md`
   - `inventory/_severity.md`, the grading rubric

   Read `METHODOLOGY.md` once for the full process.

2. MAP. Make the worklist complete. Enumerate every attacker-influenced entrypoint
   into `inventory/_surface.md` and fill `inventory/_auth_model.md` with the access
   model and trust boundaries. For anything the seeded units miss, add a unit file by
   copying the mandate from a seeded one: non-HTTP sources such as deserializers,
   queues, file parsers, or webhooks, entrypoint modules no guide flagged, and sequence units
   for a multi-step flow whose invariant spans several endpoints. Every entrypoint in
   the surface must be owned by some unit.

3. FAN OUT. This step is mechanical, not a matter of judgment. For EVERY unit in
   `units/` with `- Status: open`, launch one sub-review as a Task subagent, in
   parallel. One subagent per unit, no unit skipped, no two merged to save calls.
   Give each only its unit file, which carries the mandate and the files to own, plus
   the shared `_stack.md`, `inventory/_auth_model.md`, `inventory/_severity.md`, and
   `_vulnerabilities.md`. Each
   sub-review reads its files, traces into the managers, dao, controllers, and
   libraries they call, hunts the high-impact classes, verifies each control on the
   code it actually reads, refutes its own candidates, grades every real finding by
   the rubric, CRITICAL through LOW, never refuted for low impact, writes each to
   `issues/<name>.md`, and flips its unit to `- Status: reviewed`.

   Do NOT review units in this main context, only orchestrate. After the first pass,
   run more passes giving the units a different lead lens each time, authorization,
   then replay, then concurrency, then data exposure, then business logic, adding only
   findings not already in `issues/`. The union grows along a different axis each pass.
   Stop when two consecutive passes add no new issue.

4. FINALIZE. In code, do not dedup or verify in prose. Once the fan-out has covered the
   surface, run:

   ```
   codejury review repo $ARGUMENTS --workspace /var/tmp/codejury-review --finalize --reviewer claude-cli
   ```

   This is deterministic and resumable: it dedups the findings by location and class,
   adversarially verifies each survivor, drops the refuted into `_refuted.md`, and
   writes the ranked `findings.json`. The skeptic traces across files and judges against
   production semantics, so a `select_for_update` held inside a `transaction.atomic` is
   recognised as safe, not a race. Re-run it to resume if a usage
   limit interrupts, findings already verified are skipped. Your job is the fan-out. The
   dedup, verification, and report are the code's job.

5. GATE. Let codejury, not your judgment, decide whether the review may stop:

   ```
   codejury review repo $ARGUMENTS --workspace /var/tmp/codejury-review --gate
   ```

   If it exits non-zero it lists what is unmet: the surface not enumerated, a unit not
   reviewed, or a finding with no calibrated severity. Address each, then re-check.
   Only report complete once it passes. It is a floor, not proof of recall, so keep
   accumulating diverse passes.

PoC and the operator. Write a runnable PoC per finding. Run a PoC only when it needs
no input from me, and never against production. A stateful PoC must run against an
environment that models production locking, not a SQLite stand-in. When only a runtime
fact I hold can settle a finding, mark it `blocked` with the exact `Needs:` and grade
it on the conservative assumption. Gather every such need into one list for a
follow-up run I start later, do not pause to ask me mid-run.

End with one report and then stop: confirmed findings as a table of title, class,
`file:line`, severity, and status, the blocked findings each with its `Needs:`, the
consolidated verification-needs list, and the coverage, units reviewed over units in
the inventory. The issue files live in the workspace `issues/`. Do not ask me to
continue, just finish and report.
