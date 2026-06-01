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
  form and need upgrading to spec; determinism, SARIF, and baseline are new.
- **P1 -- Context / code-graph engine.** Cross-file source->sink tracing
  (tree-sitter / scope + import graph) to give the model provenance (is a value
  attacker-controlled?). This is the real fix for the taint floor. Start from the
  existing `scan --callers/--callees` cross-file context.
- **P2 -- Verification / proof.** For high-severity VULNERABLE, generate and run a
  PoC in an isolated sandbox to separate "proven exploitable" from "suspected".
  Sandbox never touches real environment / network / credentials.
- **P3 -- AI-era capabilities.** New capability YAML for the OWASP LLM Top 10
  (prompt_injection, insecure_output_handling, excessive_agency, rag_poisoning,
  mcp_security, prompt_secret_leak, model_supply_chain), each with golden samples.
- **P4 -- Workflow & scale.** PR bot (inline review + gate -- *partially done*:
  GitHub review and `--fail-on` exist); diff baseline (report only new issues);
  autofix; adaptive orchestration (escalate to debate only when disputed or
  high-risk); cheap static pre-filter + tiered models for cost.
- **P5 -- Self-improvement loop.** Mine missed CVEs into new capability patterns,
  propose as PRs, merge only when eval passes. Guardrail: never edit the golden
  set or scoring to "pass" (see CLAUDE.md invariant 5).

## Thresholds

Set during P0 baseline calibration (human-signed). Until then they are
placeholders -- do not invent values.

| Gate | Metric | Threshold |
|---|---|---|
| Unlock P1 | per-capability P/R/F1 baseline recorded | TBD (P0 baseline) |
| P1 accept | taint-class precision uplift vs baseline | X (TBD) |
| P2 accept | proven-exploitable rate on high-severity | Y (TBD) |
| P4 accept | latency / cost / cost-reduction ratio | Z (TBD) |
| P3 accept | new-capability P/R parity with ASVS capabilities | TBD |
