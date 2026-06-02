# codejury

AI code security review, in two paths matched to their nature:

- **Diff review** (coded): audit a pull request's diff for newly introduced,
  exploitable risks. A single balanced LLM call, or an adversarial
  Finder/Challenger/Judge pass for higher coverage and fewer false positives.
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
codejury audit --diff-file changes.diff

# audit a git range in a repo
codejury audit --repo /path/to/app --git-range origin/main...HEAD

# from stdin
git diff HEAD~1 | codejury audit

# adversarial mode: Finder + Challenger + Judge (higher coverage, lower FP, ~3x cost)
codejury audit --diff-file changes.diff --mode adversarial

# CI gate + SARIF
codejury audit --diff-file changes.diff --format sarif --fail-on high
```

Configure a backend with `--provider`/`--model`/`--api-key`/`--api-base` or the
`CODEJURY_API_KEY` / `CODEJURY_MODEL` / `CODEJURY_API_BASE` environment variables.
`codejury dry-run` exercises the engine with a mock provider and no key.

## Whole-repo review

```bash
codejury full-review /path/to/your/repo
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
