```text
 ██████╗ ██████╗ ██████╗ ███████╗     ██╗██╗   ██╗██████╗ ██╗   ██╗
██╔════╝██╔═══██╗██╔══██╗██╔════╝     ██║██║   ██║██╔══██╗╚██╗ ██╔╝
██║     ██║   ██║██║  ██║█████╗       ██║██║   ██║██████╔╝ ╚████╔╝
██║     ██║   ██║██║  ██║██╔══╝  ██   ██║██║   ██║██╔══██╗  ╚██╔╝
╚██████╗╚██████╔╝██████╔╝███████╗╚█████╔╝╚██████╔╝██║  ██║   ██║
 ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝
```

[![Tests](https://img.shields.io/github/actions/workflow/status/aiseclabs/codejury/test.yml?branch=main&label=tests)](https://github.com/aiseclabs/codejury/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/codejury)](https://pypi.org/project/codejury/)
[![Python](https://img.shields.io/pypi/pyversions/codejury)](https://pypi.org/project/codejury/)
[![License](https://img.shields.io/pypi/l/codejury)](https://github.com/aiseclabs/codejury/blob/main/LICENSE)

AI-assisted security review for code diffs and whole repositories.

The tool has two review paths:

- **Diff Review** audits a pull request or unified diff in one command.
- **Repository Review** fans out across a whole repository, reviews focused units, deduplicates
  candidates, verifies findings, and checks coverage with a gate.

Diff Review is fast and reads only the change, so it catches what is visible in the diff.
Cross-file business logic and invariants that span files need context from across the
repository, which is Repository Review's job, so a clean Diff Review does not by itself clear the
repository.

Security knowledge is data. Vulnerability classes, language guides, framework guides, and
protocol guides live in markdown under each review domain's `knowledge/` directory, for
example `codejury/domains/web/knowledge/`, so adding a stack or class is usually a data
change rather than a Python code change. The `web` domain is the default and `evm` reviews
Solidity smart contracts, selected with `--domain` or detected automatically.

## Install

The simplest install pulls everything, every model backend plus the optional toolchains, so no
capability is missing:

```bash
pip install "codejury[all]"
```

To keep it lean, install only the pieces you need instead. At least one model backend is required:

```bash
pip install "codejury[anthropic]"   # or "codejury[openai]" or "codejury[litellm]"
```

Then add optional capabilities as you need them:

```bash
pip install "codejury[evm]"         # a Slither call graph backend for Solidity, grounds EVM review
pip install "codejury[claude-sdk]"  # a persistent Claude Code subscription transport
```

Install the Repository Review slash command for an agent:

```bash
codejury install-slash-command                  # Claude Code
codejury install-slash-command --agent codex    # Codex
```

`install-slash-command` copies `/codejury-review` into the selected agent's command
directory. The one command dispatches by argument: a directory runs the Repository Review
fan-out, a diff file or git range runs the coded Diff Review. Pass `--dir` to install it
somewhere else.

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

Each role takes a full backend, the same five fields as the base, every one unset by default:
`CODEJURY_<ROLE>_PROVIDER`, `_MODEL`, `_API_KEY`, `_API_BASE`, `_WIRE_API`, with `<ROLE>` one of
`FINDER`, `CHALLENGER`, `JUDGE`, and the matching `--<role>-provider`, `--<role>-model`,
`--<role>-api-key`, `--<role>-api-base`, `--<role>-wire-api` flags. An unset field inherits the
base, so you set none of these for a single-model run and override only the seat you want to
change. The key and the api-base inherit the base only when the role keeps the base provider. A
role that switches vendor brings its own key, since the base key belongs to the base vendor. For
example a Claude base finder challenged by GPT and confirmed by Claude:

```bash
export CODEJURY_CHALLENGER_PROVIDER=openai
export CODEJURY_CHALLENGER_MODEL=...             # a GPT model, the skeptic
export CODEJURY_CHALLENGER_API_KEY=...
export CODEJURY_CHALLENGER_WIRE_API=responses    # the gpt-5 reasoning models speak Responses
export CODEJURY_JUDGE_MODEL=...                  # a Claude model, the confirmer, distinct from the challenger
```

The same `CODEJURY_FINDER_*` / `CODEJURY_CHALLENGER_*` / `CODEJURY_JUDGE_*` and the matching
`--finder-* / --challenger-* / --judge-*` flags work on both `review diff` and `review repository`.
Note that `review repository --run` finds with one model, the finder, it no longer adds a second
co-finder, and a seat that runs on the subscription supplies its own review, so it ignores
that seat's backend flags while the others still apply.

The tool does not auto-load `.env`.

Useful flags:

- `--provider anthropic|openai|litellm`
- `--model <model>`
- `--api-key <key>`
- `--api-base <url>`
- `--retries <n>`
- `--timeout <seconds>`

## Diff Review

Diff Review is the fast coded path. It audits a unified diff with either a standard
single model call or an adversarial Finder, Challenger, and Judge pass.

```bash
# review a diff file
codejury review diff --file changes.diff

# review a git range
codejury review diff --repository /path/to/app --git-range origin/main...HEAD

# review stdin
git diff HEAD~1 | codejury review diff

# use adversarial mode for extra recall on subtle cross-file logic
codejury review diff --file changes.diff --mode adversarial

# emit SARIF and fail on HIGH or CRITICAL findings
codejury review diff --file changes.diff --format sarif --fail-on high

# review with no provider key, riding your Claude Code subscription
codejury review diff --file changes.diff --executor subscription

# carry fetched source provenance into the report, see Fetch Verified Source
codejury review diff --file changes.diff --source-meta target/codejury-source.json

# run adversarial mode with a keyless Claude finder and judge plus an OpenAI challenger on its own key
codejury review diff --file changes.diff --mode adversarial \
  --challenger-provider openai --challenger-api-key "$OPENAI_API_KEY"
```

Diff Review takes the same `--executor auto|api|subscription` as Repository Review, see Review
Strategy. The default `auto` calls the provider when a seat has a key and falls back to your
Claude Code subscription for a keyless Anthropic seat. Unlike the repository agent, the diff agent
answers from the diff in the prompt and reads no files.

`codejury review diff --dry-run` uses a mock provider and a built-in demo diff, so it needs
no API key.

## Repository Review

Repository Review is the recall-first path for whole repositories. A whole codebase is too large
for one useful model call, so the tool creates a workspace, builds a unit worklist, and
reviews focused units instead of doing one shallow pass.

Start by scaffolding a workspace:

```bash
codejury review repository /path/to/repository
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
/codejury-review /path/to/repository
```

The agent maps the attack surface, fills the authorization model, runs one focused
sub-review per unit, records findings, and leaves deterministic post-processing to code.
PoCs must run only against sandbox or dev environments, never production.

After the fan-out review, run the coded finalization and gate:

```bash
codejury review repository /path/to/repository --finalize
codejury review repository /path/to/repository --gate
```

`--finalize` deduplicates candidate files, verifies survivors, writes the confirmed
`findings/`, records refuted candidates in `_refuted.md` and PoC reconciliation in
`_pocs.md`, and writes ranked `findings.json`. `--gate` fails until the workspace has an
enumerated surface, reviewed units, and calibrated candidates. Add `--strict-coverage` to
also fail when a source file is owned by no unit, instead of noting it.

Add `--poc` on finalize to generate and run an executable PoC for each confirmed finding
when the domain binds a PoC backend, such as the EVM Foundry reproducer. It is off by
default since it calls a model and a compiler per finding. A PoC runs locally only, it never
forks a network, broadcasts, or holds a key, and it only adds evidence, so a finding is kept
whether or not its PoC reproduces.

For a headless run, use:

```bash
codejury review repository /path/to/repository --run
```

### Review Strategy

A `--run` chooses how each unit is reviewed:

- `--executor auto` is the default. Each seat, the finder and the skeptic, calls the
  provider when it has a reachable key and falls back to a headless `claude -p`
  subscription agent for a keyless Anthropic seat, so a keyless run works with no provider
  key. A keyless non-Anthropic seat, such as an OpenAI finder with no key, is a loud error,
  it has no subscription to fall back to. This is what lets a Claude finder ride your
  subscription while an OpenAI challenger uses its own key.
- `--executor api` makes one grounded model call per unit and requires a key, a missing key
  is a loud startup error, the same point as auto. Facts ground that call in a tool-extracted
  call graph, storage layout, and read and write sets when the domain binds a facts backend,
  such as the EVM Slither backend, which is what gives a smart contract review its call
  relationships and co-locates a cross-function path the file slices would otherwise split.
  A domain with a backend, the EVM domain, grounds with facts by default, except at `--effort
  low`, the cheap fast tier where the pass stays file-slice only. When the toolchain is absent
  or the target does not compile the review degrades to file-slice review with a loud note
  rather than failing. Pass `--no-facts` to force it off for a faster pass, or `--facts` to
  force it on where it is not the default.
- `--executor subscription` always runs each unit and its verification as a headless
  `claude -p` agent that reads and traces the files itself with read-only tools, using your
  Claude Code access and no provider key. Use it when you want a tool-using agent rather
  than a single grounded call even where a key is present.

The subscription backend starts a fresh `claude -p` process for every call by default. A
Repository Review run makes many calls, so to amortize that startup set
`CODEJURY_CLAUDE_TRANSPORT=sdk`, which keeps a Claude Agent SDK session alive across calls
after you install `codejury[claude-sdk]`. The default `process` transport is unchanged, and
an unknown transport value fails at startup rather than silently falling back.

`--effort low|medium|high` is the one depth dial, each level fixing three things at once:

| `--effort` | Shots per lens | Skeptics to drop a candidate | Facts default |
|:---|:---|:---|:---|
| `low` | 1 | 1 | Off |
| `medium` (default) | 2 | 1 | On |
| `high` | 3 | 2 | On |

`--min-lens-shots` and `--votes` override the shot and skeptic columns, and `--facts` or
`--no-facts` overrides the facts column.

On the subscription backend the concurrency within a pass defaults to 2 so a wide fan-out does not
trip the shared rate cap, and to 6 on an API key, override it with `--concurrency`.

Set a distinct `--judge-model`, the confirmer, from the challenger to enable cross-model
verification. The challenger refutes a finding and the judge must agree before it is dropped,
so a deletion needs two models. With the judge not distinct from the challenger, the verify
stage refutes nothing, the recall-safe default.

## Data Boundary

The tool sends code-derived content to the model provider you configure, so know what
leaves the machine before reviewing a proprietary repository:

- Diff Review on the `api` row sends the unified diff under review. On the `subscription`
  row it sends the diff in the `claude -p` prompt through your Claude Code account, and the
  diff agent uses no file tools, so only the diff text leaves the machine, not local files.
- Under the default `--executor auto`, each seat follows the `api` row when it has a key
  and the `subscription` row when it falls back to your Claude Code subscription, so what
  leaves the machine is decided per seat by whether that seat has a key.
- Repository Review with `--executor api` sends bounded source snippets, the detected stack
  notes, the vulnerability guidance, and the findings.
- Verification with `--executor api` sends the cited source file and the finding
  details. On the `subscription` row, Claude Code receives the finding details and reads
  the code itself through its read-only tools.
- A repository seat on the `subscription` row does not use the configured provider key. It runs
  Claude Code with read-only file tools, and Claude Code may send prompts and the code it
  reads through your Claude Code account, so the code does not stay local. The diff agent is
  narrower, it reads no files and sees only the diff in the prompt.

A custom `--api-base` or a LiteLLM proxy becomes part of the trust boundary, so the data
above also reaches that gateway. Prefer the `CODEJURY_API_KEY` environment variable over
`--api-key`, since a flag can leak through shell history and process listings. The review
workspace and the generated reports hold exploit paths, sensitive file locations, and
PoCs, so treat them as sensitive. The workspace is created private, mode `0700`.

## Fetch Verified Source

Review a deployed contract by first pulling its verified source from a block explorer, then
running Repository Review on the local tree:

```bash
codejury fetch source --chain eth --address 0x... --out ./target
codejury review repository ./target --domain evm --run
```

`fetch source` queries the Etherscan V2 API, which serves every supported chain from one
endpoint with one key, so a single `CODEJURY_ETHERSCAN_API_KEY` covers `eth`, `bsc`, and
`polygon`, chosen with `--chain`. Pass the key with `--api-key` or that environment variable.
It writes the reconstructed source tree and a `codejury-source.json` recording the chain,
address, compiler, and source URL, and it fails loud on an unverified or malformed response.
It never runs a review on its own. Point Diff Review at that metadata file with
`--source-meta` to carry the provenance into the report.

## Supported Knowledge

The tool selects a review domain with `--domain`, `auto` by default. The `web` domain is
the default for application code. The `evm` domain reviews Solidity smart contracts for
classes such as reentrancy, access control, oracle manipulation, accounting precision, and
signature replay.

Current guide coverage in the web domain includes:

- Python: Django, Flask, FastAPI, Celery
- Go: Gin, Echo
- JavaScript and TypeScript: Express, NestJS
- Protocols: OAuth, OIDC, GraphQL, and MCP

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
