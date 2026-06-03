# codejury

AI code security review, in two paths matched to their nature:

- **Diff review** (coded): audit a pull request's diff for newly introduced,
  exploitable risks. A single balanced LLM call (the default), or an adversarial
  Finder/Challenger/Judge pass that trades roughly 3x the cost for extra recall
  on subtle, cross-cutting flaws.
- **Whole-repo review** (agent-driven): a methodology an interactive agent
  (Claude Code, Codex) runs to traverse a codebase from its API entrypoints,
  verify issues with a real PoC, and iterate over rounds with a persistent
  memory. Too large for a single LLM call, so codejury ships the methodology and
  scaffolds the workspace rather than running a pipeline.

Security knowledge lives in **rich rules** (`codejury/data/rules/*.md`, with
per-language vulnerable/secure examples), injected into the audit prompt, not
buried in code.

## Install

```bash
pip install codejury                 # core
pip install "codejury[anthropic]"    # or [openai] / [litellm] for a backend
```

## Diff review

```bash
# audit a diff file
codejury review diff --diff-file changes.diff

# audit a git range in a repo
codejury review diff --repo /path/to/app --git-range origin/main...HEAD

# from stdin
git diff HEAD~1 | codejury review diff

# adversarial mode: Finder + Challenger + Judge (extra recall on subtle flaws, ~3x cost)
codejury review diff --diff-file changes.diff --mode adversarial

# CI gate + SARIF
codejury review diff --diff-file changes.diff --format sarif --fail-on high
```

Configure a backend with `--provider`/`--model`/`--api-key`/`--api-base` or the
`CODEJURY_API_KEY` / `CODEJURY_MODEL` / `CODEJURY_API_BASE` environment variables.
`codejury review diff --dry-run` exercises the engine with a mock provider and
no key (it uses a built-in demo diff when you do not pass one).

### Choosing a model and mode

Detection quality is dominated by the model first, then the mode. On real-diff
probes:

- A strong model (Claude Sonnet tier) in **standard** mode caught every planted
  vulnerability with near-zero false positives. A weaker model raised false
  positives in both modes, so the model is the lever that matters most.
- **Adversarial** mode did not lower false positives over standard on those
  probes and costs ~3x. Reach for it for extra recall on subtle, cross-file
  logic, not as a false-positive reducer.

Default to **standard mode with a strong model** (set it with `--model` or
`CODEJURY_MODEL`). False positives are held down by the do-not-report list and
the post-filter, not by the mode.

### Use in CI (GitHub Actions)

Audit every pull request and surface findings in the code scanning tab. Copy
[`examples/codejury-pr-review.yml`](examples/codejury-pr-review.yml) into
`.github/workflows/`, add a `CODEJURY_API_KEY` repo secret, and it will:

1. diff the PR against its base (`--git-range origin/<base>...HEAD`),
2. write SARIF and upload it with `github/codeql-action/upload-sarif`,
3. fail the check on a HIGH or CRITICAL finding (`--fail-on high`).

The job makes one model call per PR (standard mode); the SARIF is uploaded even
when the gate fails, so findings always show up on the PR.

## Whole-repo review

```bash
codejury review repo /path/to/your/repo
```

This scaffolds a review workspace (`api/`, `issues/`, `analysis/`, and a
`security-review-memory.md`), seeds the API inventory from a deterministic scan,
and prints the methodology. Run it with an interactive agent: it reads the
methodology and the rules, traverses the code from its API entrypoints, records
high-confidence issues with a PoC, and asks you to confirm credentials or false
positives along the way. Nothing runs against production.

## Findings

Each finding carries a file and line, a severity and category, a concrete
exploit scenario, a recommendation, and a confidence. A false-positive filter
drops test/mock-path and low-confidence noise; the model is also told not to
report dependency CVEs, style notes, speculation, or config-leak-only risks.

## Extending

Add a vulnerability class by dropping a new `codejury/data/rules/<class>.md` with
the standard frontmatter (title, impact, tags, triggers) and vulnerable/secure
examples. It is data; no code change needed.
