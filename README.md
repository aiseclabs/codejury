```
 ██████╗ ██████╗ ██████╗ ███████╗     ██╗██╗   ██╗██████╗ ██╗   ██╗
██╔════╝██╔═══██╗██╔══██╗██╔════╝     ██║██║   ██║██╔══██╗╚██╗ ██╔╝
██║     ██║   ██║██║  ██║█████╗       ██║██║   ██║██████╔╝ ╚████╔╝
██║     ██║   ██║██║  ██║██╔══╝  ██   ██║██║   ██║██╔══██╗  ╚██╔╝
╚██████╗╚██████╔╝██████╔╝███████╗╚█████╔╝╚██████╔╝██║  ██║   ██║
 ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝
```

> AI code security review for diffs and whole repositories.

codejury runs two paths matched to their nature.

- **Diff review** is coded. It audits a pull request diff for newly introduced
  exploitable risk, as a single balanced LLM call or an adversarial Finder,
  Challenger, and Judge pass that trades roughly 3x the cost for extra recall on
  subtle flaws that span files.
- **Repo review** is agent driven. It is a methodology an interactive agent such
  as Claude Code or Codex runs to map a codebase attack surface, trace inputs to
  sinks across files, verify issues with a real PoC, and iterate over rounds with
  a persistent memory. A whole repository is too large for one LLM call, so
  codejury ships the methodology and scaffolds the workspace instead of running a
  pipeline.

Security knowledge lives in rich rules under `codejury/data/rules/*.md`, with a
vulnerable and a secure example per language, injected into the audit prompt
rather than buried in code.

## Install

```bash
pip install codejury                 # core
pip install "codejury[anthropic]"    # add a backend, also openai or litellm
```

## Diff review

```bash
# audit a diff file
codejury review diff --diff-file changes.diff

# audit a git range in a repo
codejury review diff --repo /path/to/app --git-range origin/main...HEAD

# from stdin
git diff HEAD~1 | codejury review diff

# adversarial mode, more recall on subtle flaws, about 3x the cost
codejury review diff --diff-file changes.diff --mode adversarial

# CI gate and SARIF
codejury review diff --diff-file changes.diff --format sarif --fail-on high
```

Configure a backend with `--provider`, `--model`, `--api-key`, `--api-base`, or
the `CODEJURY_API_KEY`, `CODEJURY_MODEL`, and `CODEJURY_API_BASE` environment
variables. `codejury review diff --dry-run` exercises the engine with a mock
provider and no key, and falls back to a built in demo diff when you pass none.

### Choosing a model and mode

Detection quality is dominated by the model first, then the mode. On real diff
probes:

- A strong model at the Claude Sonnet tier in standard mode caught every planted
  vulnerability with almost no false positives. A weaker model raised false
  positives in both modes, so the model is the lever that matters most.
- Adversarial mode did not lower false positives over standard on those probes
  and costs about 3x. Reach for it to gain recall on subtle logic that spans
  files, not as a way to cut false positives.

Default to standard mode with a strong model, set with `--model` or
`CODEJURY_MODEL`. False positives are held down by the do not report list and the
post filter, not by the mode.

### Use in CI with GitHub Actions

Audit every pull request and surface findings in the code scanning tab. Copy
`examples/codejury-pr-review.yml` into `.github/workflows/`, add a
`CODEJURY_API_KEY` repository secret, and it will

1. diff the pull request against its base with `--git-range origin/<base>...HEAD`,
2. write SARIF and upload it with `github/codeql-action/upload-sarif`,
3. fail the check on a HIGH or CRITICAL finding with `--fail-on high`.

The job makes one model call per pull request in standard mode. The SARIF is
uploaded even when the gate fails, so findings always show up on the pull
request.

## Repo review

```bash
codejury review repo /path/to/your/repo
```

This scaffolds a review workspace with `entrypoints/`, `issues/`, `analysis/`,
and a `security-review-memory.md`, seeds the entrypoint inventory from a
deterministic scan, and prints the methodology. Run it with an interactive agent.
It reads the methodology and the rules, maps the attack surface, traces inputs to
sinks across files, records high confidence issues with a PoC, and asks you to
confirm credentials or false positives along the way. Nothing runs against
production.

## Findings

Each finding carries a file and line, a severity and category, a concrete exploit
scenario, a recommendation, and a confidence. A false positive filter drops test
paths, mock paths, and low confidence noise. The model is also told not to report
dependency CVEs, style notes, speculation, or risks that only matter when
production config leaks.

## Extending

Add a vulnerability class by dropping a new file `codejury/data/rules/<class>.md`
with the standard frontmatter of title, impact, tags, and triggers plus a
vulnerable and a secure example. It is data, no code change needed.
