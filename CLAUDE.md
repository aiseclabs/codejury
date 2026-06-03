# CLAUDE.md

An AI code security review tool. Two paths matched to their nature: a
coded **diff-audit engine** and an agent-driven **whole-repo review
methodology**. This file is loaded every session and takes precedence over
default behavior. Strategy: see `ROADMAP.md`.

## Invariants, Never Violate

1. **Knowledge is rich vulnerability classes, in data.** Security knowledge lives in
   `codejury/data/vulnerabilities/*.md`, with rich per-language vulnerable and secure examples, and
   in the prompts that reference them, not hardcoded in Python. The agent
   methodology lives in `codejury/data/methodologies/`. Detection *logic* is generic,
   *what* to detect is data, reviewable in a PR. Knowledge is split by axis and
   stays decoupled: vulnerability classes name the weakness, languages and frameworks carry the
   concrete idioms and the entrypoint markers, and protocols and the methodology
   stay language-neutral. Adding a language or framework is a drop-in guide, no
   code change.
2. **Findings are real and evidenced.** Report only real, exploitable,
   high-confidence problems, each with a file location and a concrete exploit
   scenario. No location means not reportable.
3. **Sharp scope, low noise.** Hunt high-impact classes such as business logic, authz /
   IDOR, signature flaws, state bypass / replay, auth bypass, injection, mass
   assignment. Do **not** report dependency CVEs, style or best-practice notes,
   speculative issues with no concrete exploit, or config-leak-only risks.
4. **Two paths, matched to nature.** Diff review is coded, a single LLM call or the
   adversarial Finder/Challenger/Judge pass. Whole-repo review is too large for a
   single call, so it ships as a methodology an interactive agent runs, not a
   pipeline.
5. **PoC verification is human-in-the-loop and safe.** The repo-review agent
   confirms an issue with a real PoC against a sandbox/dev environment, asking the
   operator for credentials/test-data. It never touches production or real
   credentials and never runs a destructive action without explicit go-ahead.
6. **English only.** All repo code, comments, docs, and data are English, no CJK.
7. **No proprietary content.** This repo is public on PyPI/GitHub. Never put
   internal/proprietary code or data into it.

## Architecture

| Layer | Implementation | Location |
|---|---|---|
| Diff engine | standard `AuditRunner` for one call plus adversarial `AdversarialAuditRunner` Finder/Challenger/Judge, and `audit_diff` orchestration to chunk, normalize, and filter | `codejury/diff/`, `diff/runner.py` |
| Vulnerabilities | rich AppSec markdown, trigger-selected and injected into the prompt | `codejury/data/vulnerabilities/`, `diff/vulnerabilities.py` |
| Finding + report | flat `Finding`, text/markdown/json/sarif + severity gate | `codejury/domain/finding.py`, `codejury/report.py` |
| Repo review | agent methodology + memory template + workspace scaffold, no pipeline | `codejury/data/methodologies/`, `repo/scaffold.py` |
| RepoModel | language-agnostic file map, flags candidate entrypoint files via guide globs | `codejury/repo/model.py` |
| Provider | anthropic · openai · litellm · mock with retry, via a factory | `codejury/providers/` |
| JSON parsing | best-effort extraction of a JSON object from model output | `codejury/json_parse.py` |

## Commands

One verb, `review`, split by scope. `review diff` audits a unified diff via
`--diff-file`, `--repo --git-range`, or stdin, with `--mode {standard,adversarial}`.
`review repo <dir>` scaffolds a workspace and prints the methodology for an
interactive agent. `codejury --version` prints the version.
Shared `review diff` flags: `--provider {anthropic,openai,litellm}`, `--model`,
`--format {text,markdown,json,sarif}`, `--fail-on {critical,high,medium,low}`,
`--no-filter`, `--exclude PATH` repeatable, `--dry-run` for a mock provider with no
key and a built in demo diff when none is supplied.

## Conventions

- Tests run in a venv: `python -m venv .venv && . .venv/bin/activate && pip
  install -e ".[dev]" && pytest`.
- Provider keys come from the environment or flags `CODEJURY_API_BASE`,
  `CODEJURY_API_KEY`, `CODEJURY_MODEL`. The tool does NOT auto-load `.env`.
- Data ships via `[tool.setuptools.package-data] codejury = ["data/**/*.yaml",
  "data/**/*.md"]`.
- Add a vulnerability class by dropping a new `data/vulnerabilities/<class>.md` with frontmatter of title,
  impact, tags, and triggers, and a body of vulnerable and secure examples. It is data.
- Release: bump `pyproject.toml` version -> GitHub Release `vX.Y.Z` -> OIDC
  Trusted Publishing pushes to PyPI.

## Boundaries

- Real-world detection quality is what matters, measure it on real diffs, not a
  synthetic golden set.
- The model dominates detection quality, then the mode. On real-diff probes a
  strong model at the Sonnet tier in standard mode caught every planted vulnerability
  with near-zero false positives. A weaker model raised false positives in both
  modes. Default to standard mode with a strong model. The do-not-report list and
  the post-filter keep false positives down. Adversarial mode did not lower them
  over standard and costs ~3x, so reach for it for extra recall on subtle
  cross-file logic, not as a false-positive reducer.
