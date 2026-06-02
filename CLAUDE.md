# CLAUDE.md

codejury: an AI code security review tool. Two paths matched to their nature: a
coded **diff-audit engine** and an agent-driven **whole-repo review
methodology**. This file is loaded every session and takes precedence over
default behavior. Strategy: see `ROADMAP.md`.

## Invariants (never violate)

1. **Knowledge is rich rules, in data.** Security knowledge lives in
   `codejury/data/rules/*.md` (rich, per-language vulnerable/secure examples) and
   in the prompts that reference them, not hardcoded in Python. The agent
   methodology lives in `codejury/data/agent/`. Detection *logic* is generic;
   *what* to detect is data, reviewable in a PR.
2. **Findings are real and evidenced.** Report only real, exploitable,
   high-confidence problems, each with a file location and a concrete exploit
   scenario. No location means not reportable.
3. **Sharp scope, low noise.** Hunt high-impact classes (business logic, authz /
   IDOR, signature flaws, state bypass / replay, auth bypass, injection, mass
   assignment). Do **not** report dependency CVEs, style or best-practice notes,
   speculative issues with no concrete exploit, or config-leak-only risks.
4. **Two paths, matched to nature.** Diff review is coded (single LLM call or the
   adversarial Finder/Challenger/Judge pass). Whole-repo review is too large for a
   single call, so it ships as a methodology an interactive agent runs, not a
   pipeline.
5. **PoC verification is human-in-the-loop and safe.** The full-review agent
   confirms an issue with a real PoC against a sandbox/dev environment, asking the
   operator for credentials/test-data; it never touches production or real
   credentials and never runs a destructive action without explicit go-ahead.
6. **English only.** All repo code, comments, docs, and data are English; no CJK.
7. **No proprietary content.** This repo is public on PyPI/GitHub; never put
   internal/proprietary code or data into it.

## Architecture

| Layer | Implementation | Location |
|---|---|---|
| Diff engine | standard `AuditRunner` (one call) + adversarial `AdversarialAuditRunner` (Finder/Challenger/Judge) | `codejury/diff/` |
| Rules | rich AppSec markdown, trigger-selected and injected into the prompt | `codejury/data/rules/`, `diff/rules.py` |
| Finding + report | flat `Finding`; text/markdown/json/sarif + severity gate | `codejury/domain/finding.py`, `diff/report.py` |
| Full review | agent methodology + memory template + workspace scaffold (no pipeline) | `codejury/data/agent/`, `fullreview/scaffold.py` |
| RepoModel | deterministic AST entrypoint scan, seeds the API inventory | `codejury/analysis/repo_model.py` |
| Provider | anthropic · openai · litellm · mock (+ retry), via a factory | `codejury/providers/` |
| Infrastructure | JSON parsing | `codejury/infrastructure/` |

## Commands

One verb, `review`, split by scope: `review diff` (a unified diff via
`--diff-file` / `--repo --git-range` / stdin; `--mode {standard,adversarial}`)
and `review repo <dir>` (scaffold a workspace and print the methodology for an
interactive agent). `codejury --version` prints the version.
Shared `review diff` flags: `--provider {anthropic,openai,litellm}`, `--model`,
`--format {text,markdown,json,sarif}`, `--fail-on {critical,high,medium,low}`,
`--no-filter`, `--exclude PATH` (repeatable), `--dry-run` (mock provider, no
key; a built-in demo diff when none is supplied).

## Conventions

- Tests run in a venv: `python -m venv .venv && . .venv/bin/activate && pip
  install -e ".[dev]" && pytest`.
- Provider keys come from the environment / flags (`CODEJURY_API_BASE` /
  `CODEJURY_API_KEY` / `CODEJURY_MODEL`); codejury does NOT auto-load `.env`.
- Data ships via `[tool.setuptools.package-data] codejury = ["data/**/*.yaml",
  "data/**/*.md"]`.
- Add a rule by dropping a new `data/rules/<class>.md` (frontmatter: title,
  impact, tags, triggers; body: vulnerable/secure examples). It is data.
- Release: bump `pyproject.toml` version -> GitHub Release `vX.Y.Z` -> OIDC
  Trusted Publishing pushes to PyPI.

## Boundaries

- Real-world detection quality is what matters; measure it on real diffs, not a
  synthetic golden set. Favor the adversarial mode and the do-not-report list to
  keep false positives down.
