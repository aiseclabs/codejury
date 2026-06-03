# codejury Roadmap

The strategy and the "why". Companion: `CLAUDE.md` holds invariants, commands, and
architecture, loaded every session.

## Why

LLM code-security review fails in practice for predictable reasons: a single
pass is weak, thin rule schemas give the model little real guidance, and a
whole-repo audit is too large for one call. The design answers each:

- **Knowledge as rich vulnerability classes.** Per-class markdown with per-language
  vulnerable and secure examples in `data/vulnerabilities/`, injected into the prompt, beats a
  rendered checklist.
- **Adversarial diff review.** Finder as a red team, exhaustive with no self-filter,
  Challenger to rebut false positives and independently re-scan, Judge to cross
  validate, raises coverage and cuts false positives versus a single pass.
- **Agent-driven whole-repo review.** Traversing a codebase from its API
  entrypoints, following call chains, and verifying with a real PoC needs an
  interactive agent over multiple rounds, not a per-chunk LLM call. It
  ships the methodology and scaffolds the workspace.
- **Sharp scope + human-in-the-loop.** A do-not-report list and a false-positive
  filter keep noise down. The repo-review agent confirms issues with a PoC and a
  persistent memory of confirmed false positives.

## Capability Boundaries

Static AI review reliably covers code-visible classes such as injection, crypto and secret
misuse, direct auth flaws, unsafe deserialization, data leak, and bad config. It has
limited, context-dependent coverage of authorization/IDOR, business logic, race
conditions, second-order and cross-file flows, SSRF, XSS, and session handling,
which need cross-file tracing or human confirmation. It does not replace
dependency scanning, dynamic testing, pentest, or runtime defense.

## Direction

- **Diff engine**: standard + adversarial shipped. Next: tune prompts on real
  diffs, measure precision and recall on real PRs, not a synthetic corpus.
- **Vulnerabilities**: grow `data/vulnerabilities/` coverage and per-language depth, it is data.
- **Repo Review**: refine the methodology, the entrypoint seeding, and the
  review-memory loop from real audits.
- **Validation**: the real measure is efficacy on real repositories with a real
  provider, which drives prompt and vulnerability-class changes.
