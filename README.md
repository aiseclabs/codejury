# codejury

An AI security auditor for code whose knowledge lives in versioned YAML, not in
prompts. It reviews a diff or a whole repository against the OWASP ASVS and the
OWASP LLM Top 10, and reports a verdict per dimension: both what is **vulnerable**
and what is **verified safe**.

The name is the idea. Code goes before a "jury" of adversarial roles, Finder,
Challenger, and Judge, that argue and converge on a verdict.

## Why it is built this way

- **Knowledge is data.** Each OWASP ASVS area, and now the OWASP LLM Top 10, is a
  YAML capability with safe patterns, anti-patterns, CWE ids, and examples. It is
  versioned, reviewable in a PR, and editable by non-engineers, so the framework
  core stays small.
- **Verdicts, not just alerts.** Every capability yields `SECURE`, `VULNERABLE`,
  `PARTIAL`, or `NOT_PRESENT`, so a report shows what was checked and passed, not
  only what failed.
- **Composable.** Seven orchestration strategies, three model backends, and diff,
  repo, or function inputs are chosen per run and mix freely.
- **Deterministic.** Providers run at temperature 0 and verdicts are cached, so
  the same input gives the same result.

## Install

```bash
pip install codejury                 # core and CLI
pip install 'codejury[anthropic]'    # the provider you will use: anthropic, openai, or litellm
```

## Quickstart

```bash
# No API key needed: prove the pipeline runs end to end with mock layers
codejury dry-run

# A real audit of your staged changes
export ANTHROPIC_API_KEY=sk-ant-...
git diff | codejury audit --provider anthropic

# CI gate: exit 1 if a high-severity issue is found
git diff origin/main... | codejury audit --fail-on high -

# Inline review comments on a GitHub pull request, needs GITHUB_TOKEN
git diff origin/main... | codejury audit --github your-org/your-repo#123 -
```

## Commands

| Command | What it does |
|---|---|
| `codejury dry-run` | Run the mock pipeline with no key, a smoke test. |
| `codejury audit [diff]` | Audit a unified diff from a file or stdin (`-`). |
| `codejury scan <dir>` | Audit a whole directory tree, capability by capability. |
| `codejury run <task>` | Run a named task preset, see [Tasks](#tasks). |
| `codejury eval` | Score the golden cases and report precision, recall, and F1, overall and per capability. |

Shared flags: `--orchestrator`, `--provider {anthropic,openai,litellm}`,
`--model`, `--format {text,markdown,json,sarif}`.

```bash
# Multi-round adversarial debate, rendered as Markdown
git diff | codejury audit --orchestrator debate --format markdown - > report.md

# Deep whole-repo scan, scoped to a few capabilities to bound the cost
codejury scan ./myrepo --only secrets,input_validation,crypto
```

## Orchestration strategies

`--orchestrator` chooses how the agents run. They mix freely with any provider,
model, and input.

| Strategy | What it does |
|---|---|
| `single` | One verifier pass. The default for `audit`. |
| `pipeline` | One verifier, capability by capability. |
| `debate` | Finder, Challenger, and Judge argue across rounds. |
| `reflexion` | An actor and a critic iterate. |
| `challenge` | Verify, then a recall-safe refuter drops only provably-safe taint flags. |
| `taint` | Verify, then a static data-flow gate clears an `input_validation` finding only when provenance proves the value reaching the sink is constant, sanitized, or trusted. It uses cross-file caller and callee context and downgrades only on positive proof, so it removes false positives without dropping real findings. |
| `adaptive` | Run the cheap single verifier first and escalate to a full debate only when it pays off: any `VULNERABLE` verdict, or a low-confidence `PARTIAL`/`UNKNOWN` one. Clean, confident files pay a single model call. |

## CI and pull-request workflow

- `--fail-on {critical,high,medium,low}` exits 1 when a finding at or above that
  severity is present, so the audit gates a build.
- `--github owner/repo#number` posts a review with inline comments on a pull
  request, using `GITHUB_TOKEN`.
- `--baseline <report.json>` reports only findings new since a saved report. Save
  the target branch once, then a PR shows only what it introduced, matched by a
  line-tolerant fingerprint so shifted code is not re-reported. Combine with
  `--fail-on` to gate on new issues only.

  ```bash
  git checkout main && codejury scan . --format json > baseline.json
  git checkout pr-branch && codejury scan . --baseline baseline.json --fail-on high
  ```

- `--format sarif` emits a SARIF 2.1.0 log that validates against the official
  schema, for CI and security dashboards. Each problem with a code location
  becomes a result carrying its capability as the rule id, the CWE, and a precise
  location.
- Findings in known-noise categories such as availability and DoS, rate limiting,
  and memory safety outside C and C++ are dropped by versioned rules in
  `codejury/data/suppressions.yaml`. Disable with `--no-suppress`.

## Determinism and caching

Providers query at temperature 0, and `audit` and `scan` cache each verdict on a
hash of the normalized code, the in-scope capability fingerprints, and the
orchestration. Re-auditing unchanged code returns the recorded verdicts without
re-querying the model. Editing a capability YAML changes its fingerprint and
invalidates affected entries. Pass `--no-cache` to always re-query.

## Configuration

Provider keys are read from the environment. codejury does **not** auto-load
`.env`; copy `.env.example` and `source` it.

| Variable | Used by |
|---|---|
| `ANTHROPIC_API_KEY` | `--provider anthropic` |
| `OPENAI_API_KEY` | `--provider openai` |
| `CODEJURY_API_BASE`, `CODEJURY_API_KEY`, `CODEJURY_MODEL` | defaults for `--api-base`, `--api-key`, and `--model`, for any provider |

The `CODEJURY_*` variables make a LiteLLM proxy a one-liner:

```bash
# with CODEJURY_API_BASE, CODEJURY_API_KEY, CODEJURY_MODEL in a sourced .env
git diff | codejury audit --provider litellm -
```

## Tasks

A task is a named preset of capabilities, orchestrator, provider, and model. It
lives in a YAML file. The API key always stays in the environment.

```yaml
# mytasks/proxy_scan.yaml  ->  codejury run proxy_scan --tasks mytasks
name: proxy_scan
orchestrator: debate
provider: litellm
model: your-alias
api_base: https://litellm.example.com   # key comes from CODEJURY_API_KEY
capabilities: [authn, input_validation, secrets]   # omit to check all
```

## Capabilities

The library covers all 11 OWASP ASVS areas plus a growing set of OWASP LLM Top 10
capabilities, one YAML each under `codejury/data/capabilities/`. These ids are
what `--only` and a task's `capabilities:` accept:

`authn`, `authz`, `session`, `input_validation`, `output_encoding`, `crypto`,
`secrets`, `data_protection`, `error_logging`, `business_logic`,
`dependency_config`, `prompt_injection`, `insecure_output_handling`,
`excessive_agency`, `model_supply_chain`.

To tune for your codebase, edit these files, adding patterns or sharpening
wording. No code change is needed.

## eval

`codejury eval` scores the golden cases and reports a confusion matrix with
precision, recall, and F1, overall and per capability. It takes `--dataset <dir>`
for the golden directory, `--split <name>` to score only cases tagged with that
`split:` such as a held-out set, `--orchestrator` to measure any strategy, and
`--format {text,json}`. The JSON report is a stable, documented schema.

## Architecture

```
Layer 5  Task            preset: source, capabilities, orchestrator, agents
Layer 4  Capability      YAML domain knowledge: authn, authz, prompt_injection, ...
Layer 3  Orchestrator    strategy: single, pipeline, debate, reflexion, challenge, taint, adaptive
         Source          input: diff, repo, function
         Agent           role: finder, challenger, judge, verifier, refuter
Layer 2  Provider        model backend: anthropic, openai, litellm, mock
Layer 1  Infrastructure  cross-cutting utilities: json parsing, verdict cache, retry
         Analysis        provenance and taint code-graph engine
```

Layers talk only through typed data, and each is an abstract base class plus
implementations, so the axes of task, orchestration, model, and input compose
independently.

## Limitations

- **Prompts are a first pass.** Expect false positives and misses on real code.
  Tune by editing the capability YAML and growing the golden set, and measure the
  effect with `codejury eval`.
- **Local-pattern checks are sharper than data-flow ones.** A capability judged
  from one spot, such as weak crypto or a hardcoded secret, is reliable. Taint
  classes such as path traversal and SSRF over-flag in single-file review because
  the verifier cannot see whether a value is attacker-controlled. `--orchestrator
  taint` adds a static provenance gate that clears findings it can prove safe and
  is recall-safe, but it is shallow on real code where the value flows through
  object or module attributes. Decisive taint precision needs a deeper code
  graph, which is in progress.
- **`scan` cost scales with files times capabilities.** It is a periodic deep
  audit, not a quick check, so scope it with `--only`. Day to day, audit the diff.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```
