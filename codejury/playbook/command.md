---
description: Run a codejury whole-repo security review on a repository, interactively
---
Run a codejury whole-repo security review of: $ARGUMENTS

1. Scaffold the workspace:

   ```
   codejury review repo $ARGUMENTS --workspace /var/tmp/codejury-review
   ```

   If `codejury` is not on PATH it is a pip-installed console script, so activate
   the project venv first, for example `. .venv/bin/activate`, or run it through
   that venv's Python, for example `python -m codejury`.

   If the output reports that a previous review's output is already in the
   workspace, ask me whether to clear it and start fresh. If I say yes, re-run the
   same command with `--fresh`, which clears the prior issues, PoCs, round ledger,
   and MEMORY.md for a clean slate. If I say no, continue and build on what is
   there.

2. Read `<workspace>/METHODOLOGY.md` and follow it to completion. It is the single
   source of truth for how to run the review, the entrypoint map, the trace
   targets, the Authorization Model pass, the dependency-control checks, the round
   ledger, and the Completeness Gate. Do not improvise a different process.

   Run every round to the Completeness Gate on your own and do not stop to ask me
   anything mid-run. Do not pause between rounds, do not stop early because a round
   felt productive, and do not report the review done until the gate passes. When
   you lack an input to grade a finding, proceed on the conservative assumption
   that makes it exploitable and note the assumption.

3. Write a real PoC per issue, then refute each finding before reporting it: from a
   fresh skeptical read, try to prove it is a false positive against the traps in
   `_false_positive_traps.md`. Set `Status: confirmed` if it survives, `refuted` if
   the refutation kills it and then do not report it, or `blocked` with the exact
   `Needs:` when only a runtime fact I hold can settle it. Run a PoC only when it
   needs no input from me, and never against production. The blocked findings are
   settled in a separate follow-up run I start later.

4. End with one report and then stop: confirmed findings, blocked findings each
   with its `Needs:`, and one consolidated verification-needs list of what a
   follow-up run requires, the per-PoC credentials, the trust-boundary questions,
   and the candidate false positives. Present it as a table: title, class,
   `file:line`, exploit, status. The issue files live in the workspace `issues/`.
   Do not ask me to continue, just finish and report.
