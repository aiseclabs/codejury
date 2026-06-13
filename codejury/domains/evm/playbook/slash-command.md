---
description: Run a codejury whole-protocol smart contract security review, interactively, by fanning out per contract
---
Run a codejury whole-protocol smart contract security review of: $ARGUMENTS

You are the orchestrator, not the reviewer. Recall comes from fanning out: the tool gives
you a deterministic unit worklist, you run one focused sub-review per contract in parallel,
union their findings across diverse passes, verify, and stop on a gate. The deep reading
happens inside each sub-review, never in this main context.

1. SCAFFOLD. Build the workspace and the deterministic worklist:

   ```
   codejury review repo $ARGUMENTS --domain evm
   ```

   The workspace defaults to a user-private directory under `XDG_STATE_HOME` or
   `~/.local/state`, the same path for every step below. Pass `--workspace <path>` to
   override it. If `codejury` is not on PATH, activate the project venv first, for example
   `. .venv/bin/activate`, or run `python -m codejury`. If it reports a previous review's
   output, ask me whether to clear it, and if I say yes, re-run with `--fresh`.

   RESUMING. If a previous run was interrupted, run this command again without clearing.
   It resumes: a unit already marked `- Status: reviewed` is skipped, and `--finalize`
   does not re-verify a settled finding. Keep resuming in new sessions until the gate
   passes.

   The scaffold writes, ready for you:

   - `units/`, one unit per candidate contract carrying its deep-review mandate and `- Status: open`
   - `inventory/_surface.md`, the coverage denominator
   - `inventory/_auth_model.md`, for the role and ownership model
   - `inventory/_severity.md`, the fund-loss grading rubric

   Read `METHODOLOGY.md` once for the full process.

2. MAP. Make the worklist complete. Enumerate every external and public function, plus
   `fallback` and `receive`, into `inventory/_surface.md`, and fill `inventory/_auth_model.md`
   with the role and ownership model and the value map. For anything the seeded units miss,
   add a unit file by copying the mandate from a seeded one: contracts no glob flagged, and
   sequence units for a multi-step or multi-contract flow whose invariant spans several
   calls. Every entrypoint in the surface must be owned by some unit.

3. FAN OUT. This step is mechanical, not a matter of judgment. For every unit in `units/`
   with `- Status: open`, launch one sub-review per unit as a separate subagent, in
   parallel. One per unit, no unit skipped. Give each only its unit file plus the shared
   `_stack.md`, `inventory/_auth_model.md`, `inventory/_severity.md`, and
   `_vulnerabilities.md`. Each sub-review reads its files, traces into inherited base
   contracts, libraries, and called contracts, hunts the high-impact classes, reentrancy,
   access control, oracle manipulation, accounting, proxy and initializer flaws, signature
   replay, unchecked calls, DoS, verifies each control on the code it reads, refutes its own
   candidates, grades every real finding by the rubric, writes each to `candidates/<name>.md`
   with its proof at `pocs/<name>.<ext>`, and flips its unit to `- Status: reviewed`.

   Do not review units in this main context, only orchestrate. After the first pass, run
   more passes giving the units a different lead lens each time, access control, then
   reentrancy, then oracle manipulation, then accounting, then signatures, adding only
   findings not already in `candidates/`. Stop when two consecutive passes add no new issue.

4. FINALIZE. In code, do not dedup or verify in prose. Once the fan-out has covered the
   surface, run:

   ```
   codejury review repo $ARGUMENTS --domain evm --finalize
   ```

   In Claude Code, add `--reviewer claude-cli` to verify through your Claude Code access
   with no provider key. This dedups by location and class, adversarially verifies each
   survivor, drops the refuted into `_refuted.md`, and writes the ranked `findings.json`.
   Re-run it to resume if interrupted.

5. GATE. Let codejury decide whether the review may stop:

   ```
   codejury review repo $ARGUMENTS --domain evm --gate
   ```

   If it exits non-zero it lists what is unmet: the surface not enumerated, a unit not
   reviewed, or a finding with no calibrated severity. Address each, then re-check. Only
   report complete once it passes.

Proof and safety. Write a runnable Foundry proof per finding. Run a proof only against a
local `anvil` fork or a fresh local deploy, never against mainnet or a live deployment.
Never broadcast a transaction, never hold or use a private key. When only a deploy or
runtime fact settles a finding, which oracle is wired in, a deployed address, mark it
`blocked` with the exact `Needs:` and grade it on the conservative assumption. Gather every
such need into one list for a follow-up run, do not pause to ask me mid-run.

End with one report and then stop: confirmed findings as a table of title, class,
`file:line`, severity, and status, the blocked findings each with its `Needs:`, the
consolidated verification-needs list, and the coverage. Do not ask me to continue, just
finish and report.
