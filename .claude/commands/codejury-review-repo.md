---
description: Run a codejury whole-repo security review on a repository, interactively
---
Run a codejury whole-repository security review of: $ARGUMENTS

1. Scaffold the workspace:

   ```
   codejury review repo $ARGUMENTS --workspace /tmp/codejury-review
   ```

   If `codejury` is not on PATH it is a pip-installed console script, so activate
   the project venv first, for example `. .venv/bin/activate`, or run it through
   that venv's Python, for example `python -m codejury`.

2. Read `<workspace>/METHODOLOGY.md` and follow it to completion. It is the single
   source of truth for how to run the review, the entrypoint map, the trace
   targets, the Authorization Model pass, the dependency-control checks, the round
   ledger, and the Completeness Gate. Do not improvise a different process.

3. Verify each issue with a real PoC, human in the loop. Ask me for any
   credential, test account, or MFA step you need. Never touch production, never
   use real credentials, and never run a destructive action without my go-ahead.
   Only a reproduced PoC is a confirmed finding.

4. Report confirmed findings, the ones with a reproduced PoC, separately from
   suspected ones still blocked on verification, as a table: title, class,
   `file:line`, exploit, verification status. The issue files live in the
   workspace `issues/`.
