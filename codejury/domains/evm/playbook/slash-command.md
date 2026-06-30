---
description: Run a codejury smart contract security review of a diff or a whole repository
---
Run a codejury smart contract security review of: $ARGUMENTS

First decide which path $ARGUMENTS names, the two are different tools, do not mix them.

- DIFF REVIEW when $ARGUMENTS is a unified diff file such as a `.diff` or `.patch`, a single
  file of diff text, or a git range such as `origin/main...HEAD`. This path is fully coded,
  you run one command and relay its report, there is no fan-out and no workspace.
- REPO REVIEW when $ARGUMENTS is a directory, a whole protocol to audit. This path is the
  fan-out you orchestrate, follow the numbered steps under Repo Review.

## Diff Review

Run the coded engine and relay its report. There is nothing for you to judge, the engine
chunks the diff, runs its passes, filters, and prints the findings.

```
codejury review diff --file <the diff file> --domain evm
```

For a git range instead of a file, drop `--file` and pass the range, with `--repo` if the
repository is not the current directory:

```
codejury review diff --repo <repo dir> --git-range origin/main...HEAD --domain evm
```

If `codejury` is not on PATH it is a pip-installed console script, so activate the project
venv first, for example `. .venv/bin/activate`, or run `python -m codejury`.

Relay the report as it prints. A failed, rate-limited, blank, or error-exited run is a
failed review, not a clean pass, surface the error and never report zero findings from a
broken run. A non-zero exit means a finding hit the severity gate or the audit degraded, say
which. Then stop, Diff Review does not use the units, the workspace, or the gate below.

## Repo Review

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
   - `inventory/_invariants.md`, the operator-seeded intent invariants, optional
   - `inventory/_severity.md`, the fund-loss grading rubric

   Read `METHODOLOGY.md` once for the full process.

2. MAP. Make the worklist complete. Enumerate every external and public function, plus
   `fallback` and `receive`, into `inventory/_surface.md`, and fill `inventory/_auth_model.md`
   with the role and ownership model and the value map. If the operator seeded
   `inventory/_invariants.md` with intent invariants, leave it for the units to check, and
   if it is blank do not invent rows, an unseeded invariants file changes nothing. For anything the seeded units miss,
   add a unit file by copying the mandate from a seeded one: contracts no glob flagged, and
   sequence units for a multi-step or multi-contract flow whose invariant spans several
   calls. Every entrypoint in the surface must be owned by some unit.

3. FAN OUT. This step is mechanical, not a matter of judgment. For every unit in `units/`
   with `- Status: open`, launch one sub-review per unit as a separate subagent, in
   parallel. One per unit, no unit skipped. Give each only its unit file plus the shared
   `_stack.md`, `inventory/_auth_model.md`, `inventory/_invariants.md`,
   `inventory/_severity.md`, and `_vulnerabilities.md`. Each sub-review reads its files, traces into inherited base
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

   In Claude Code, add `--executor subscription` to verify through your Claude Code access
   with no provider key. This dedups by location and class, adversarially verifies each
   survivor, drops the refuted into `_refuted.md`, and writes the ranked `findings.json`.
   Re-run it to resume if interrupted.

   Cross-model verification. With `--executor subscription` the skeptic is Claude, the same
   family that found the issue, so its blind spots are shared. Name a different vendor in the
   challenger seat to get an independent skeptic, Claude finds, GPT challenges, Claude confirms,
   by running finalize with the model reviewer:

   ```
   CODEJURY_PROVIDER=anthropic CODEJURY_MODEL=<a claude model> \
   CODEJURY_CHALLENGER_PROVIDER=openai CODEJURY_CHALLENGER_MODEL=<a gpt model> CODEJURY_CHALLENGER_WIRE_API=responses \
   CODEJURY_JUDGE_PROVIDER=anthropic CODEJURY_JUDGE_MODEL=<a claude model> \
   codejury review repo $ARGUMENTS --domain evm --finalize --executor api
   ```

   The challenger GPT refutes and the judge Claude confirms, so a finding is dropped only when
   two different vendors agree. The judge must be a distinct model from the challenger, else
   nothing is refuted. Set the OpenAI and Anthropic keys in the environment.

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
