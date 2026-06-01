# codejury Roadmap

The strategy and the "why". Companion: `CLAUDE.md` (invariants / commands /
boundaries, loaded every session). Detailed, executable specs that turn this
roadmap into self-checkable work units (closed by `codejury eval`) are kept in a
separate planning document.

## Why

LLM code-security review usually fails because the security knowledge is buried
in prompts: unversioned, unshareable, untunable by non-engineers, and drifting on
every edit. codejury makes the knowledge **data** -- one versioned YAML capability
per OWASP ASVS area -- and keeps the engine small and composable (orchestration /
model / input axes mix freely). Quality is governed by an evaluation harness, not
by vibes.

## Current status (0.5.1)

Built and shipped:

- **Engine**: 5 orchestrators (single, pipeline, debate, reflexion, challenge);
  4 providers (anthropic, openai, litellm, mock) + opt-in retry; sources for
  diff, function, and repo (chunking + cross-file caller/callee context).
- **Knowledge as data**: 11 ASVS capabilities + a data-driven suppression filter,
  all YAML.
- **Delivery**: CLI (`dry-run / audit / scan / run / eval`), reports in
  text / markdown / json, GitHub PR inline reviews, `--fail-on` CI gate, on PyPI
  via OIDC Trusted Publishing.

Known limitation (measured): taint-class detection (path traversal, SSRF) over-
flags in single-file LLM review and cannot be fixed by prompt/context tuning
alone -- it needs real data-flow analysis (P1). Local-pattern detection (weak
crypto, hardcoded secrets, IDOR, etc.) is reliable.

## Phases

The executable specs live in a separate planning document. High level:

- **P0 -- Trustworthy, measurable, reproducible.** Per-capability precision /
  recall / F1 eval with negatives and held-out split; a versioned, human-signed
  golden set; determinism (temperature 0 + verdict cache); SARIF output; a
  human-set baseline. *Gate to unlock P1.* Status: eval and golden exist in basic
  form and need upgrading to spec; determinism (temperature 0 + a verdict cache
  keyed on code + capability fingerprint + orchestration) and SARIF output
  (`--format sarif`) are in place; the baseline is recorded and the gate
  thresholds are human-signed (`BASELINE.md`, Thresholds below).
- **P1 -- Context / code-graph engine.** Cross-file source->sink tracing to give
  the model provenance (is a value attacker-controlled?). *Shipped a first
  engine* (`codejury/analysis/`): a Python-AST value-origin tracer, a signed
  taint vocabulary (`data/taint.yaml`), an intra-procedural + one-hop cross-file
  classifier, and the conservative `--orchestrator taint` gate. On the golden set
  it lifts input_validation precision 0.75 -> 1.00 with recall held (clears the
  P1 gate). P1-05 measured the real-repo gap (python-multipart CVE-2026-24486):
  the one-hop AST engine is too shallow for sink paths built from instance/config
  attributes, so the gate is recall-safe but inert there. *Remaining*: a deeper
  graph (multi-hop + attribute/field tracking, tree-sitter for other languages)
  is the real fix; the conservative gate must not be loosened at recall's expense.
- **P2 -- Verification / proof.** For high-severity VULNERABLE, generate and run a
  PoC in an isolated sandbox to separate "proven exploitable" from "suspected".
  Sandbox never touches real environment / network / credentials.
- **P3 -- AI-era capabilities.** New capability YAML for the OWASP LLM Top 10
  (prompt_injection, insecure_output_handling, excessive_agency, rag_poisoning,
  mcp_security, prompt_secret_leak, model_supply_chain), each with golden samples.
- **P4 -- Workflow & scale.** PR bot (inline review + gate -- *done*: GitHub
  review, `--fail-on`, and `--baseline` diff baseline that reports only findings
  new since a saved report); *remaining*: autofix; adaptive orchestration
  (escalate to debate only when disputed or high-risk); cheap static pre-filter +
  tiered models for cost.
- **P5 -- Self-improvement loop.** Mine missed CVEs into new capability patterns,
  propose as PRs, merge only when eval passes. Guardrail: never edit the golden
  set or scoring to "pass" (see CLAUDE.md invariant 5).

## Thresholds

Calibrated from the P0-05 baseline (`BASELINE.md`, 2026-06-01) and human-signed.
The baseline reframed the P1 gate from precision to recall: on the current
corpus `input_validation` precision is 1.00 but recall is 0.67 -- the verifier
misses SSRF / insecure-deserialization sinks, so recall is the real taint gap.

| Gate | Metric | Baseline | Threshold |
|---|---|---|---|
| Unlock P1 | per-capability P/R/F1 baseline recorded | overall F1 0.91 | recorded (see `BASELINE.md`) |
| P1 accept | taint-class (`input_validation`) recall uplift, precision held | R 0.67 / P 1.00 | R >= 0.90 with P >= 0.95 |
| P2 accept | proven-exploitable rate on high-severity VULNERABLE | none yet | >= 0.80 get a passing PoC |
| P3 accept | new (LLM Top 10) capability parity with ASVS capabilities | ASVS F1 0.91 | per-capability F1 >= 0.85 |
| P4 accept | adaptive-orchestration cost cut at no quality loss | none yet | >= 40% fewer model calls vs always-debate, F1 not lower |
