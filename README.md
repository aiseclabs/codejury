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

- **Diff Review** is coded. It audits a pull request diff for newly introduced
  exploitable risk, as a single balanced LLM call or an adversarial Finder,
  Challenger, and Judge pass that trades roughly 3x the cost for extra recall on
  subtle flaws that span files. One command in, findings out.
- **Repo Review** is agent driven. A whole repository is too large for one LLM
  call, so codejury scaffolds a workspace and hands an interactive agent such as
  Claude Code or Codex a methodology to run. The agent maps the attack surface,
  traces inputs to sinks across files, verifies issues with a real PoC, and
  iterates over rounds with a persistent memory.

Security knowledge is data, not code. Vulnerability classes live in
`codejury/data/vulnerabilities/*.md` with a vulnerable and a secure example per
language, and the stack guides live under `data/languages`, `data/frameworks`,
and `data/protocols`. The engine stays language neutral and names no framework,
so adding a stack is a drop-in markdown file.

## Install

```bash
pip install codejury                       # core
pip install "codejury[anthropic]"          # add a backend, also openai or litellm
codejury install-slash-command             # Claude Code, ~/.claude/commands/
codejury install-slash-command --agent codex   # Codex, ~/.codex/prompts/
```

`install-slash-command` copies the `/codejury-review` command into the agent's
command directory. The command body is the same for every agent, only the
directory differs, so pass `--dir` for any other agent. The repo review itself is
agent neutral, so even without the command you can run `codejury review` and
tell any agent to follow the methodology it writes.

## Diff Review

```bash
# audit a diff file
codejury diff --diff-file changes.diff

# audit a git range in a repo
codejury diff --repo /path/to/app --git-range origin/main...HEAD

# from stdin
git diff HEAD~1 | codejury diff

# adversarial mode, more recall on subtle flaws, about 3x the cost
codejury diff --diff-file changes.diff --mode adversarial

# CI gate and SARIF
codejury diff --diff-file changes.diff --format sarif --fail-on high
```

Configure a backend with `--provider`, `--model`, `--api-key`, `--api-base`, or
the `CODEJURY_API_KEY`, `CODEJURY_MODEL`, and `CODEJURY_API_BASE` environment
variables. `codejury diff --dry-run` exercises the engine with a mock
provider and no key, and falls back to a built in demo diff when you pass none.

### Choosing a Model and Mode

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

## Repo Review

Repo Review does not scan and print findings. It sets up a review for an agent to
run, because a whole repository needs many rounds of reading, cross-file tracing,
and PoC work that an agent does, not a single call.

```bash
codejury review /path/to/your/repo
```

This detects the stack, seeds the entrypoint inventory and the downstream trace
targets from a deterministic scan, writes the methodology to
`<workspace>/METHODOLOGY.md`, and prints a short pointer. It creates the
workspace:

```
entrypoints/   the candidate entrypoint files to start from
issues/        one write-up per confirmed or suspected issue
pocs/          a runnable PoC per issue, same name as the issue
analysis/      _trace_targets.md, the round ledger, and trace notes
security-review-memory.md
```

Then run it with an interactive agent. In Claude Code or Codex:

```
/codejury-review /path/to/your/repo
```

Any agent works, the slash command is just a shortcut. Without it, tell the agent
to follow the `METHODOLOGY.md` the scaffold wrote.

The agent follows `METHODOLOGY.md`: it maps the attack surface including non HTTP
sources, traces each input to its sink through the downstream layers, runs an
Authorization Model pass for missing-auth and IDOR, and follows a control into a
library when an entrypoint delegates it. It keeps going until a Completeness Gate
passes, two consecutive rounds that add nothing new. It confirms each issue with
a real PoC against a sandbox or dev environment and asks you for any credential or
test data it needs. Only a reproduced PoC is a confirmed finding, and nothing
runs against production.

The supported stacks today are Python with Django, Celery, Flask, and FastAPI,
Go with Gin and Echo, JavaScript and TypeScript with Express and NestJS, and the
OAuth and OIDC protocol. The methodology still works on an unguided stack, it just
leans more on the agent's own knowledge.

## Findings

Each finding carries a file and line, a severity and category, a concrete exploit
scenario, a recommendation, and a confidence. A false positive filter drops test
paths, mock paths, and low confidence noise. The model is also told not to report
dependency CVEs, style notes, speculation, or risks that only matter when
production config leaks.

## Extending

Knowledge is data, so extending codejury is a drop-in markdown file with no code
change.

- A vulnerability class: `codejury/data/vulnerabilities/<class>.md` with
  frontmatter of title, impact, tags, and triggers, plus a vulnerable and a
  secure example.
- A language or framework: `codejury/data/languages/<lang>.md` or
  `codejury/data/frameworks/<lang>/<framework>.md`, declaring its detect signals,
  entrypoint markers, and downstream logic layers.
- A protocol such as OAuth: `codejury/data/protocols/<name>.md`, detected by
  language neutral content tokens.
```
