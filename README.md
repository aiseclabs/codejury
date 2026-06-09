```
 ██████╗ ██████╗ ██████╗ ███████╗     ██╗██╗   ██╗██████╗ ██╗   ██╗
██╔════╝██╔═══██╗██╔══██╗██╔════╝     ██║██║   ██║██╔══██╗╚██╗ ██╔╝
██║     ██║   ██║██║  ██║█████╗       ██║██║   ██║██████╔╝ ╚████╔╝
██║     ██║   ██║██║  ██║██╔══╝  ██   ██║██║   ██║██╔══██╗  ╚██╔╝
╚██████╗╚██████╔╝██████╔╝███████╗╚█████╔╝╚██████╔╝██║  ██║   ██║
 ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝
```

AI-assisted security review for code diffs and whole repositories.

Codejury has two review paths:

- **Diff Review** audits a pull request or unified diff in one command.
- **Repo Review** fans out across a whole repository, reviews focused units, deduplicates
  candidates, verifies findings, and checks coverage with a gate.

Security knowledge is data. Vulnerability classes, language guides, framework guides, and
protocol guides live in markdown under `codejury/knowledge/`, so adding a stack or class is
usually a data change rather than a Python code change.

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

## Configure A Model Backend

Set a provider key through flags or environment variables:

```bash
export CODEJURY_API_KEY=...
export CODEJURY_MODEL=claude-sonnet-4-6
export CODEJURY_API_BASE=...   # optional gateway or proxy
```

The tool does not auto-load `.env`.

Useful flags:

- `--provider anthropic|openai|litellm`
- `--model <model>`
- `--api-key <key>`
- `--api-base <url>`
- `--retries <n>`

## Diff Review

Diff Review is the fast coded path. It audits a unified diff with either a standard
single model call or an adversarial Finder, Challenger, and Judge pass.

```bash
# Review a diff file
codejury review diff --file changes.diff

# Review a git range
codejury review diff --repo /path/to/app --git-range origin/main...HEAD

# Review stdin
git diff HEAD~1 | codejury review diff

# Use adversarial mode for extra recall on subtle cross-file logic
codejury review diff --file changes.diff --mode adversarial

# Emit SARIF and fail on HIGH or CRITICAL findings
codejury review diff --file changes.diff --format sarif --fail-on high
```

`codejury review diff --dry-run` uses a mock provider and a built-in demo diff, so it needs
no API key.

## Repo Review

Repo Review is the recall-first path for whole repositories. A whole codebase is too large
for one useful model call, so Codejury creates a workspace, builds a unit worklist, and
reviews focused units instead of doing one shallow pass.

Start by scaffolding a workspace:

```bash
codejury review repo /path/to/repo
```

The workspace contains:

```text
inventory/      attack surface, authorization model, candidates, severity rubric
units/          one review unit per candidate entrypoint
issues/         issue write-ups
pocs/           runnable PoCs, when available
METHODOLOGY.md  full review process
_stack.md       detected stack notes
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

`--finalize` deduplicates issue files, verifies survivors, records refuted candidates in
`_refuted.md`, and writes ranked `findings.json`. `--gate` fails until the workspace has
an enumerated surface, reviewed units, and calibrated findings.

For a headless run, use:

```bash
codejury review repo /path/to/repo --run
```

Use `--reviewer claude-cli` only when you want the Claude Code backend to run unit reviews
and verification through local Claude CLI access.

## Supported Knowledge

Current guide coverage includes:

- Python: Django, Flask, FastAPI, Celery
- Go: Gin, Echo
- JavaScript and TypeScript: Express, NestJS
- Protocols: OAuth and OIDC

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

Codejury is intentionally scoped to real exploitable application security issues. It should
not report dependency CVEs, style notes, generic best practices, speculation, or risks that
only matter if production configuration leaks.

## Model And Mode Guidance

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

## Extend Codejury

Add security knowledge as markdown:

- Vulnerability class:
  `codejury/knowledge/vulnerabilities/<id>.md`
- Language guide:
  `codejury/knowledge/guides/languages/<language>.md`
- Framework guide:
  `codejury/knowledge/guides/frameworks/<language>/<framework>.md`
- Protocol guide:
  `codejury/knowledge/guides/protocols/<protocol>.md`

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

Release process:

1. Bump `pyproject.toml`.
2. Create a GitHub Release named `vX.Y.Z`.
3. OIDC Trusted Publishing builds and publishes to PyPI.
