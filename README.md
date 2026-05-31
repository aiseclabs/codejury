# codejury

A general-purpose **Application Security AI audit framework**. Domain knowledge (11
capabilities aligned with OWASP ASVS) lives in versioned YAML files as
first-class data, keeping the framework core small.

The name comes from the core orchestration metaphor: code goes before a "jury"
of adversarial roles -- Finder / Challenger / Judge -- that converge on a verdict.

## Five-layer architecture

```
Layer 5  Task            task configuration (source + capabilities + orchestrator + agents)
Layer 4  Capability      YAML domain knowledge (authn / authz / input_validation ...)
Layer 3  Orchestrator    strategy (single / debate / pipeline / reflexion)
         Source          input (diff / file / repo / function)
         Agent           audit role (finder / challenger / judge / verifier)
Layer 2  Provider        model backend (anthropic / openai / litellm / mock)
Layer 1  Infrastructure  cross-cutting utilities (json parsing, ...)
```

Layers talk only through typed data. Each layer is an abstract base class (ABC)
plus implementations, so the four axes (task / orchestration / model / input)
compose independently.

## Design notes

- **Domain knowledge is data, not prompts**: a capability YAML is readable by
  the LLM, by a rule engine, and by a human, and is versioned alongside code.
- **Explains both "why it's wrong" and "why it's fine"**: every capability
  yields a `Verdict`, recording safe matches too -- a checkup dimension rather
  than an anomaly filter.

## Status

Usable end to end. Built so far:

- **Orchestrators**: single, pipeline, debate, reflexion
- **Sources**: diff, function (repo with chunking is planned)
- **Providers**: anthropic, openai, litellm, mock
- **Capabilities**: all 11 OWASP ASVS areas
- **Reporting**: text, markdown, json

Not yet built: a separate Task configuration layer (the CLI assembles the pieces
directly for now), a RepoSource, and a golden-set precision/recall harness.

## Usage

```bash
# Audit a unified diff against the capability library
git diff | codejury audit --orchestrator debate --provider anthropic --format markdown -

# No API key needed: prove the pipeline composes with mock layers
codejury dry-run
```

`audit` reads a diff from a file argument or stdin (`-`). Real providers read
their key from the environment (e.g. `ANTHROPIC_API_KEY`).

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```
