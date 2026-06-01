# codejury

An AI security auditor for code whose knowledge lives in versioned YAML, not in
prompts. It reviews a diff or a whole repository against the OWASP ASVS and
reports a verdict per dimension -- both what is **vulnerable** and what is
**verified safe**.

The name is the core idea: code goes before a "jury" of adversarial roles --
Finder / Challenger / Judge -- that argue and converge on a verdict.

Why it is built this way:

- **Knowledge is data.** Each of the 11 OWASP ASVS areas is a YAML capability
  (safe patterns + anti-patterns, with CWE and examples) -- versioned, reviewable
  in a PR, and editable by non-engineers. The framework core stays small.
- **Verdicts, not just alerts.** Every capability yields `SECURE` / `VULNERABLE`
  / `PARTIAL` / `NOT_PRESENT`, so a report shows what was checked and *passed*,
  not only what failed.
- **Composable.** Four orchestration strategies, four model backends, and
  diff / repo inputs are chosen per run -- mix and match.

## Install

```bash
pip install codejury                 # core + CLI
pip install 'codejury[anthropic]'    # the provider you'll use: anthropic | openai | litellm
```

## Quickstart

```bash
# No API key needed -- prove the pipeline runs end to end with mock layers
codejury dry-run

# A real audit: set a key, then review your staged changes
export ANTHROPIC_API_KEY=sk-ant-...
git diff | codejury audit --provider anthropic
```

## Commands

| Command | What it does |
|---|---|
| `codejury dry-run` | Run the mock pipeline with no key (smoke test). |
| `codejury audit [diff]` | Audit a unified diff from a file or stdin (`-`). |
| `codejury scan <dir>` | Audit a whole directory tree, capability by capability. |
| `codejury run <task>` | Run a named task preset (see [Tasks](#tasks)). |
| `codejury eval` | Score the golden cases and report precision / recall. |

Shared flags: `--orchestrator {single,pipeline,debate,reflexion}`,
`--provider {anthropic,openai,litellm}`, `--model`, `--format {text,markdown,json}`.

```bash
# Multi-round adversarial debate, rendered as Markdown
git diff | codejury audit --orchestrator debate --format markdown - > report.md

# Deep whole-repo scan, scoped to a few capabilities to bound the cost
codejury scan ./myrepo --only secrets,input_validation,crypto
```

## Configuration

Provider keys are read from the environment (codejury does **not** auto-load
`.env` -- copy `.env.example` and `source` it):

| Variable | Used by |
|---|---|
| `ANTHROPIC_API_KEY` | `--provider anthropic` |
| `OPENAI_API_KEY` | `--provider openai` |
| `CODEJURY_API_BASE` / `CODEJURY_API_KEY` / `CODEJURY_MODEL` | defaults for `--api-base` / `--api-key` / `--model` (any provider) |

The `CODEJURY_*` overrides make a LiteLLM proxy a one-liner:

```bash
# with CODEJURY_API_BASE / CODEJURY_API_KEY / CODEJURY_MODEL in a sourced .env
git diff | codejury audit --provider litellm -
```

## Tasks

A task is a named preset (capabilities + orchestrator + provider + model). It
lives in a YAML file; the API key always stays in the environment.

```yaml
# mytasks/proxy_scan.yaml  ->  codejury run proxy_scan --tasks mytasks
name: proxy_scan
orchestrator: debate
provider: litellm
model: your-alias
api_base: https://litellm.example.com   # key from CODEJURY_API_KEY
capabilities: [authn, input_validation, secrets]   # omit to check all
```

## Capabilities

The library covers all 11 OWASP ASVS areas, one YAML each under
`codejury/data/capabilities/`. These ids are what `--only` and a task's
`capabilities:` accept:

`authn` · `authz` · `session` · `input_validation` · `output_encoding` ·
`crypto` · `secrets` · `data_protection` · `error_logging` ·
`business_logic` · `dependency_config`

To tune for your codebase, edit these files (add patterns / sharpen wording) --
no code change needed.

## Architecture

```
Layer 5  Task            preset: source + capabilities + orchestrator + agents
Layer 4  Capability      YAML domain knowledge (authn / authz / ...)
Layer 3  Orchestrator    strategy (single / pipeline / debate / reflexion)
         Source          input (diff / repo / function)
         Agent           role (finder / challenger / judge / verifier)
Layer 2  Provider        model backend (anthropic / openai / litellm / mock)
Layer 1  Infrastructure  cross-cutting utilities (json parsing, retry, ...)
```

Layers talk only through typed data, and each is an abstract base class plus
implementations, so the axes (task / orchestration / model / input) compose
independently.

## Limitations

- **Prompts are a first pass.** Expect false positives and misses on real code.
  Tune by editing the capability YAML and growing the golden set; measure the
  effect with `codejury eval`.
- **Local-pattern checks are sharper than data-flow ones.** Capabilities judged
  from one spot (weak crypto, hardcoded secrets) are reliable; taint / data-flow
  ones like path traversal over-flag in single-file review because the verifier
  can't see whether a value is attacker-controlled. Scope them out with `--only`,
  or use `--orchestrator debate` to challenge findings.
- **`scan` cost scales as files x capabilities.** It is a periodic deep audit,
  not a quick check -- scope it with `--only`. Day to day, audit the diff.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```
