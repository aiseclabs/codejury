```text
 ██████╗ ██████╗ ██████╗ ███████╗     ██╗██╗   ██╗██████╗ ██╗   ██╗
██╔════╝██╔═══██╗██╔══██╗██╔════╝     ██║██║   ██║██╔══██╗╚██╗ ██╔╝
██║     ██║   ██║██║  ██║█████╗       ██║██║   ██║██████╔╝ ╚████╔╝
██║     ██║   ██║██║  ██║██╔══╝  ██   ██║██║   ██║██╔══██╗  ╚██╔╝
╚██████╗╚██████╔╝██████╔╝███████╗╚█████╔╝╚██████╔╝██║  ██║   ██║
 ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝
```

[![Tests](https://img.shields.io/github/actions/workflow/status/aiseclabs/codejury/test.yml?label=tests)](https://github.com/aiseclabs/codejury/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/codejury)](https://pypi.org/project/codejury/)
[![Python](https://img.shields.io/pypi/pyversions/codejury)](https://pypi.org/project/codejury/)
[![License: MIT](https://img.shields.io/pypi/l/codejury)](https://github.com/aiseclabs/codejury/blob/main/LICENSE)

AI-assisted security review for code diffs and whole repositories.

The tool has two review paths:

- **Diff Review** audits a pull request or unified diff in one command.
- **Repo Review** fans out across a whole repository, reviews focused units, deduplicates
  candidates, verifies findings, and checks coverage with a gate.

Security knowledge is data. Vulnerability classes, language guides, framework guides, and
protocol guides live in markdown under each review domain's `knowledge/` directory, for
example `codejury/domains/web/knowledge/`, so adding a stack or class is usually a data
change rather than a Python code change. The `web` domain is the default and `evm` reviews
Solidity smart contracts, selected with `--domain` or detected automatically.

## Install

Install the core package and one model backend:

```bash
pip install codejury
pip install "codejury[anthropic]"   # or "codejury[openai]" or "codejury[litellm]"
```

Install the Repo Review slash command for an agent:

```bash
codejury install-slash-command                  # Claude Code
codejury install-slash-command --agent codex    # Codex
```

`install-slash-command` copies `/codejury-review-repo` into the selected agent's command
directory. Pass `--dir` to install it somewhere else.

## Configure a Model Backend

Set a provider key through flags or environment variables:

```bash
export CODEJURY_MODEL=claude-opus-4-8
export CODEJURY_API_KEY=...
export CODEJURY_API_BASE=...   # optional gateway or proxy
```

Both review paths name three model roles, finder, challenger, and judge. The finder finds, the
challenger refutes, the judge confirms before a deletion. Each role defaults to the base
`--model`, so a single-model run sets only `--model`. Put a different vendor in any seat for
cross-model review, where uncorrelated blind spots catch what one model misses, and a deletion
needs the judge to be a distinct model from the challenger so no lone skeptic drops a real
finding. With the judge not distinct, nothing is refuted, the recall-safe default.

Each role takes a full backend override, all defaulting to the base. For example a Claude base
finder challenged by GPT and confirmed by Claude:

```bash
export CODEJURY_CHALLENGER_PROVIDER=openai
export CODEJURY_CHALLENGER_MODEL=...         # a GPT model, the skeptic
export CODEJURY_CHALLENGER_API_KEY=...
export CODEJURY_CHALLENGER_WIRE_API=responses   # the gpt-5 reasoning models speak Responses
export CODEJURY_JUDGE_MODEL=...              # a Claude model, the confirmer, distinct from the challenger
```

The same `CODEJURY_FINDER_*` / `CODEJURY_CHALLENGER_*` / `CODEJURY_JUDGE_*` and the matching
`--finder-* / --challenger-* / --judge-*` flags work on both `review diff` and `review repo`.
Note that `review repo --run` finds with one model, the finder, it no longer adds a second
co-finder, and `--reviewer claude-cli` supplies the finder and skeptic itself, so it ignores
the finder and challenger flags while the judge still applies.

The tool does not auto-load `.env`.

Useful flags:

- `--provider anthropic|openai|litellm`
- `--model <model>`
- `--api-key <key>`
- `--api-base <url>`
- `--retries <n>`

## Data Boundary

The tool sends code-derived content to the model provider you configure, so know what
leaves the machine before reviewing a proprietary repository:

- Diff Review sends the unified diff under review.
- Repo Review with `--reviewer model` sends bounded source snippets, the detected stack
  notes, the vulnerability guidance, and the findings.
- Verification with `--reviewer model` sends the cited source file and the finding
  details. With `--reviewer claude-cli`, Claude Code receives the finding details and
  reads the code itself through its read-only tools.
- `--reviewer claude-cli` does not use the configured provider key. It runs Claude Code
  with read-only file tools, and Claude Code may send prompts and the code it reads
  through your Claude Code account, so the code does not stay local.

A custom `--api-base` or a LiteLLM proxy becomes part of the trust boundary, so the data
above also reaches that gateway. Prefer the `CODEJURY_API_KEY` environment variable over
`--api-key`, since a flag can leak through shell history and process listings. The review
workspace and the generated reports hold exploit paths, sensitive file locations, and
PoCs, so treat them as sensitive. The workspace is created private, mode `0700`.

## Diff Review

Diff Review is the fast coded path. It audits a unified diff with either a standard
single model call or an adversarial Finder, Challenger, and Judge pass.

```bash
# review a diff file
codejury review diff --file changes.diff

# review a git range
codejury review diff --repo /path/to/app --git-range origin/main...HEAD

# review stdin
git diff HEAD~1 | codejury review diff

# use adversarial mode for extra recall on subtle cross-file logic
codejury review diff --file changes.diff --mode adversarial

# emit SARIF and fail on HIGH or CRITICAL findings
codejury review diff --file changes.diff --format sarif --fail-on high
```

`codejury review diff --dry-run` uses a mock provider and a built-in demo diff, so it needs
no API key.

## Repo Review

Repo Review is the recall-first path for whole repositories. A whole codebase is too large
for one useful model call, so the tool creates a workspace, builds a unit worklist, and
reviews focused units instead of doing one shallow pass.

Start by scaffolding a workspace:

```bash
codejury review repo /path/to/repo
```

The workspace contains:

```text
inventory/      attack surface, authorization model, seeded entrypoints, severity rubric
units/          one review unit per candidate entrypoint
candidates/     agent proposals, one write-up per candidate finding
findings/       confirmed findings, written by finalize
pocs/           runnable PoCs, when available
findings.json   ranked machine-readable findings
METHODOLOGY.md  full review process
_stack.md       detected stack notes
_refuted.md     refuted candidates and why
_pocs.md        PoC reconciliation, planned versus delivered
```

Then run the interactive slash command in Claude Code or Codex:

```text
/codejury-review-repo /path/to/repo
```

The agent maps the attack surface, fills the authorization model, runs one focused
sub-review per unit, records findings, and leaves deterministic post-processing to code.
PoCs must run only against sandbox or dev environments, never production.

After the fan-out review, run the coded finalization and gate:

```bash
codejury review repo /path/to/repo --finalize
codejury review repo /path/to/repo --gate
```

`--finalize` deduplicates candidate files, verifies survivors, writes the confirmed
`findings/`, records refuted candidates in `_refuted.md` and PoC reconciliation in
`_pocs.md`, and writes ranked `findings.json`. `--gate` fails until the workspace has an
enumerated surface, reviewed units, and calibrated candidates.

For a headless run, use:

```bash
codejury review repo /path/to/repo --run
```

### Review Strategy

A `--run` chooses how each unit is reviewed:

- `--reviewer model` is the default. It makes one grounded model call per unit. Add
  `--facts` to ground that call in a tool-extracted call graph, storage layout, and read
  and write sets when the domain binds a facts backend, such as the EVM Slither backend.
  This is what gives a smart contract review its call relationships, so prefer
  `--run --facts` on Solidity.
- `--reviewer claude-cli` runs each unit and its verification as a headless `claude -p`
  agent that reads and traces the files itself with read-only tools, using your Claude Code
  access and no provider key. Use it when you want a tool-using agent rather than a single
  grounded call.

Set a distinct `--judge-model`, the confirmer, from the challenger to enable cross-model
verification. The challenger refutes a finding and the judge must agree before it is dropped,
so a deletion needs two models. With the judge not distinct from the challenger, the verify
stage refutes nothing, the recall-safe default.

## Supported Knowledge

The tool selects a review domain with `--domain`, `auto` by default. The `web` domain is
the default for application code. The `evm` domain reviews Solidity smart contracts for
classes such as reentrancy, access control, oracle manipulation, accounting precision, and
signature replay.

Current guide coverage in the web domain includes:

- Python: Django, Flask, FastAPI, Celery
- Go: Gin, Echo
- JavaScript and TypeScript: Express, NestJS
- Protocols: OAuth and OIDC

The evm domain ships a Solidity guide and the smart contract vulnerability classes above.
Unguided stacks still work, but the agent relies more on general methodology and model
knowledge.

## Findings

Every reportable finding should have:

- file and line
- severity
- category
- exploit scenario
- recommendation
- confidence or verification status

The tool is intentionally scoped to real exploitable application security issues. It should
not report dependency CVEs, style notes, generic best practices, speculation, or risks that
only matter if production configuration leaks.

## Model and Mode Guidance

Detection quality is dominated by model quality first, then mode.

- Use standard mode with a strong model by default.
- Use adversarial mode when you want extra recall on subtle cross-file logic.
- Do not use adversarial mode as a false-positive reducer. False positives are controlled
  by the do-not-report guidance, deterministic filtering, and verification.

## GitHub Actions

Use the example workflow:

```bash
cp examples/codejury-pr-review.yml .github/workflows/codejury-pr-review.yml
```

Add `CODEJURY_API_KEY` as a repository secret. The workflow reviews the pull request diff,
uploads SARIF to code scanning, and fails on HIGH or CRITICAL findings.

## Extend the Knowledge

Add security knowledge as markdown:

- Vulnerability class:
  `codejury/domains/<domain>/knowledge/vulnerabilities/<id>.md`
- Language guide:
  `codejury/domains/<domain>/knowledge/guides/languages/<language>.md`
- Framework guide:
  `codejury/domains/<domain>/knowledge/guides/frameworks/<language>/<framework>.md`
- Protocol guide:
  `codejury/domains/<domain>/knowledge/guides/protocols/<protocol>.md`

Keep frontmatter and detection signals data-driven. Avoid adding language, framework, or
vulnerability-specific detection logic to Python unless the engine itself needs a generic
capability.

## Development

Run tests in a virtual environment:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
pytest
```
