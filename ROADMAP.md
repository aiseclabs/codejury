# codejury Roadmap

The strategy and the "why". Companion: `CLAUDE.md` (invariants / commands /
architecture, loaded every session).

## Why

LLM code-security review fails in practice for predictable reasons: a single
pass is weak, thin rule schemas give the model little real guidance, and a
whole-repo audit is too large for one call. codejury answers each:

- **Knowledge as rich rules.** Per-class markdown with per-language
  vulnerable/secure examples (`data/rules/`), injected into the prompt, beats a
  rendered checklist.
- **Adversarial diff review.** Finder (red team, exhaustive, no self-filter),
  Challenger (rebut false positives and independently re-scan), Judge (cross
  validate) raises coverage and cuts false positives versus a single pass.
- **Agent-driven whole-repo review.** Traversing a codebase from its API
  entrypoints, following call chains, and verifying with a real PoC needs an
  interactive agent over multiple rounds, not a per-chunk LLM call. codejury
  ships the methodology and scaffolds the workspace.
- **Sharp scope + human-in-the-loop.** A do-not-report list and a false-positive
  filter keep noise down; the full-review agent confirms issues with a PoC and a
  persistent memory of confirmed false positives.

## Capability boundaries (honest)

Static AI review reliably covers code-visible classes (injection, crypto/secret
misuse, direct auth flaws, unsafe deserialization, data-leak, bad config). It has
limited, context-dependent coverage of authorization/IDOR, business logic, race
conditions, second-order and cross-file flows, SSRF, XSS, and session handling,
which need cross-file tracing or human confirmation. It does not replace
dependency scanning, dynamic testing, pentest, or runtime defense.

## Direction

- **Diff engine**: standard + adversarial shipped. Next: tune prompts on real
  diffs, measure precision/recall on real PRs (not a synthetic corpus).
- **Rules**: grow `data/rules/` coverage and per-language depth; it is data.
- **Full review**: refine the methodology, the API-inventory seeding, and the
  review-memory loop from real audits.
- **Validation**: the real measure is efficacy on real repositories with a real
  provider; that drives prompt and rule changes.
