# codejury

An AI security auditor for code whose knowledge lives in versioned YAML, not in
prompts. It reviews a diff or a whole repository against the OWASP ASVS and
reports a verdict per dimension: both what is **vulnerable** and what is
**verified safe**.

The name is the core idea: code goes before a "jury" of adversarial roles,
Finder / Challenger / Judge, that argue and converge on a verdict.

Why it is built this way:

- **Knowledge is data.** Each OWASP ASVS area (and now OWASP LLM Top 10 areas) is a YAML capability
  (safe patterns + anti-patterns, with CWE and examples), versioned, reviewable
  in a PR, and editable by non-engineers. The framework core stays small.
- **Verdicts, not just alerts.** Every capability yields `SECURE` / `VULNERABLE`
  / `PARTIAL` / `NOT_PRESENT`, so a report shows what was checked and *passed*,
  not only what failed.
- **Composable.** Four orchestration strategies, four model backends, and
  diff / repo inputs are chosen per run; mix and match.

## Install

```bash
pip install codejury                 # core + CLI
pip install 'codejury[anthropic]'    # the provider you'll use: anthropic | openai | litellm
```

## Quickstart

```bash
# CI gate: exit 1 if a high-severity issue is found
git diff origin/main... | codejury audit --fail-on high -

# Post inline review comments on a GitHub pull request (needs GITHUB_TOKEN)
git diff origin/main... | codejury audit --github your-org/your-repo#123 -

# No API key needed: prove the pipeline runs end to end with mock layers
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
| `codejury eval` | Score the golden cases; report precision / recall / F1, overall and per capability. |

Shared flags: `--orchestrator {single,pipeline,debate,reflexion,challenge,taint,adaptive}`,
`--provider {anthropic,openai,litellm}`, `--model`,
`--format {text,markdown,json,sarif}`.

`audit`/`scan` take `--baseline <report.json>`: save a JSON report of the target
branch, then on a PR report only findings new since it (matched by a
line-tolerant fingerprint, so shifted code is not re-reported). Pair with
`--fail-on` to gate CI on new issues only:

```bash
git checkout main && codejury scan . --format json > baseline.json
git checkout pr-branch && codejury scan . --baseline baseline.json --fail-on high
```

`--orchestrator taint` adds a data-flow gate: after the verifier rules, it clears
an `input_validation` finding only when static provenance analysis proves the
value reaching the sink is constant, sanitized, or trusted (using cross-file
caller/callee context). It downgrades only on positive proof, so it removes false
positives without dropping real findings.

`--orchestrator adaptive` keeps cost down: it runs the single verifier first and
escalates to a full debate only for artifacts worth it: any VULNERABLE verdict
(verify a flag before reporting) or a low-confidence PARTIAL/UNKNOWN one. Clean,
confident files pay a single call; only the rest pay for debate.

`--format sarif` emits a SARIF 2.1.0 log (validates against the official schema)
for CI and security dashboards: each problem with a code location becomes a
result carrying its capability (as the rule id), CWE, and a precise location.

Findings in known-noise categories (availability/DoS, rate limiting, memory safety
outside C/C++) are dropped by versioned rules in
`codejury/data/suppressions.yaml`; disable with `--no-suppress`.

`codejury eval` takes `--dataset <dir>` (golden YAML directory), `--split <name>`
(score only cases tagged with that `split:`, e.g. a held-out set), and
`--format {text,json}`; the JSON report is a stable schema (overall plus
per-capability confusion matrix and precision / recall / F1).

Runs are deterministic: providers query at temperature 0, and `audit` / `scan`
cache each verdict on a hash of the normalized code, the in-scope capability
versions, and the orchestration. Re-auditing unchanged code returns the recorded
verdicts without re-querying the model; editing a capability YAML changes its
fingerprint and invalidates affected entries. Pass `--no-cache` to always
re-query.

```bash
# Multi-round adversarial debate, rendered as Markdown
git diff | codejury audit --orchestrator debate --format markdown - > report.md

# Deep whole-repo scan, scoped to a few capabilities to bound the cost
codejury scan ./myrepo --only secrets,input_validation,crypto
```

## Configuration

Provider keys are read from the environment (codejury does **not** auto-load
`.env`; copy `.env.example` and `source` it):

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

The library covers all 11 OWASP ASVS areas plus a growing set of OWASP LLM Top 10
capabilities, one YAML each under `codejury/data/capabilities/`. These ids are
what `--only` and a task's `capabilities:` accept:

`authn` · `authz` · `session` · `input_validation` · `output_encoding` ·
`crypto` · `secrets` · `data_protection` · `error_logging` ·
`business_logic` · `dependency_config` · `prompt_injection` ·
`insecure_output_handling` · `excessive_agency`

To tune for your codebase, edit these files (add patterns / sharpen wording);
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
  can't see whether a value is attacker-controlled. Mitigations that add context
  but do not fully solve it: `scan --callers` (where this file's functions are
  called) and `scan --callees` (the called code it delegates to, so a sink in
  another file is visible); pair them for both directions; `--orchestrator
  challenge` (a recall-safe
  refutation pass that drops only provably-safe flags); `--only` to scope; or
  `--orchestrator debate`. Real taint precision still needs data-flow analysis,
  not model skepticism.
- **`scan` cost scales as files x capabilities.** It is a periodic deep audit,
  not a quick check; scope it with `--only`. Day to day, audit the diff.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```
