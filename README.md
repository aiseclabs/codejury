```
 ██████╗ ██████╗ ██████╗ ███████╗     ██╗██╗   ██╗██████╗ ██╗   ██╗
██╔════╝██╔═══██╗██╔══██╗██╔════╝     ██║██║   ██║██╔══██╗╚██╗ ██╔╝
██║     ██║   ██║██║  ██║█████╗       ██║██║   ██║██████╔╝ ╚████╔╝
██║     ██║   ██║██║  ██║██╔══╝  ██   ██║██║   ██║██╔══██╗  ╚██╔╝
╚██████╗╚██████╔╝██████╔╝███████╗╚█████╔╝╚██████╔╝██║  ██║   ██║
 ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝
```

An AI code security review tool. It works two ways. `review diff` audits a pull
request diff for newly introduced exploitable risk in one command. `review repo`
sets up an interactive agent such as Claude Code or Codex to audit a whole
repository, mapping the attack surface, tracing inputs to sinks across files, and
verifying each issue with a real PoC.

Security knowledge is data, not code. Drop-in markdown guides hold the
vulnerability classes, languages, frameworks, and protocols, so the engine names
no language and adding a stack is a new file.

## Install

```bash
pip install codejury                       # core
pip install "codejury[anthropic]"          # add a backend, also openai or litellm
codejury install-slash-command             # Claude Code, ~/.claude/commands/
codejury install-slash-command --agent codex   # Codex, ~/.codex/prompts/
```

`install-slash-command` copies the `/codejury-review-repo` command into the
agent's command directory. The command body is the same for every agent, only the
directory differs, so pass `--dir` for any other agent.

## Diff Review

The coded engine. It audits a diff in one command, as a single balanced LLM call
or an adversarial Finder, Challenger, and Judge pass that trades roughly 3x the
cost for extra recall on subtle flaws that span files.

```bash
# a diff file
codejury review diff --file changes.diff

# a git range in a repo
codejury review diff --repo /path/to/app --git-range origin/main...HEAD

# from stdin
git diff HEAD~1 | codejury review diff

# adversarial mode, more recall on subtle flaws, about 3x the cost
codejury review diff --file changes.diff --mode adversarial

# CI gate and SARIF
codejury review diff --file changes.diff --format sarif --fail-on high
```

Configure a backend with `--provider`, `--model`, `--api-key`, `--api-base`, or
the `CODEJURY_API_KEY`, `CODEJURY_MODEL`, and `CODEJURY_API_BASE` environment
variables. `codejury review diff --dry-run` exercises the engine with a mock
provider and no key, and falls back to a built in demo diff when you pass none.

## Repo Review

The agent path. A whole repo is too large for one LLM call, so this sets up a
review for an interactive agent rather than running a pipeline.

```bash
codejury review repo /path/to/your/repo
```

It detects the stack, seeds the entrypoint inventory and the downstream trace
targets from a deterministic scan, writes the methodology to
`<workspace>/METHODOLOGY.md`, and prints a short pointer. The workspace:

```
entrypoints/   the candidate entrypoint files to start from
issues/        one write-up per confirmed or suspected issue
pocs/          a runnable PoC per issue, same name as the issue
analysis/      _trace_targets.md, the round ledger, and trace notes
METHODOLOGY.md and MEMORY.md
```

Then run it with an interactive agent. In Claude Code or Codex:

```
/codejury-review-repo /path/to/your/repo
```

Any agent works, the slash command is just a shortcut. Without it, tell the agent
to follow the `METHODOLOGY.md` the scaffold wrote. The agent maps the attack
surface including non HTTP sources, traces each input to its sink through the
downstream layers, runs an Authorization Model pass for missing-auth and IDOR,
and follows a control into a library when an entrypoint delegates it. It iterates
until a Completeness Gate passes, confirms each issue with a real PoC against a
sandbox or dev environment, and asks you for any credential it needs. Only a
reproduced PoC is a confirmed finding, and nothing runs against production.

The supported stacks today are Python with Django, Celery, Flask, and FastAPI,
Go with Gin and Echo, JavaScript and TypeScript with Express and NestJS, and the
OAuth and OIDC protocol. The methodology still works on an unguided stack, it just
leans more on the agent's own knowledge.

## Choosing a Model and Mode

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

## Use in CI with GitHub Actions

Audit every pull request and surface findings in the code scanning tab. Copy
`examples/codejury-pr-review.yml` into `.github/workflows/`, add a
`CODEJURY_API_KEY` repository secret, and it will

1. diff the pull request against its base with `--git-range origin/<base>...HEAD`,
2. write SARIF and upload it with `github/codeql-action/upload-sarif`,
3. fail the check on a HIGH or CRITICAL finding with `--fail-on high`.

The job makes one model call per pull request in standard mode. The SARIF is
uploaded even when the gate fails, so findings always show up on the pull
request.

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
