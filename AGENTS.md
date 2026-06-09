# AGENTS.md

Project instructions for coding agents. Codex reads `AGENTS.md` directly. Claude Code
reads it through the `@AGENTS.md` import in `CLAUDE.md`.

Codejury is an AI-assisted security review tool for code diffs and whole repositories.
Diff Review is the coded path. Repo Review is the fan-out path where code owns the
deterministic orchestration and agents or model calls provide per-unit judgment.

## Non-Negotiable Invariants

1. **Knowledge is data, the engine is generic.** Security knowledge belongs in
   `codejury/knowledge/` markdown and in prompts that reference it. Do not hardcode
   language, framework, or vulnerability-specific detection logic in Python. Adding a
   stack or vulnerability class should usually be a data change.
2. **Findings are real, evidenced, and scoped.** Report only exploitable,
   high-confidence issues with a concrete file location and exploit scenario. No
   location means not reportable. Prioritize high-impact classes such as business
   logic, authorization, IDOR, signature flaws, replay, authentication bypass,
   injection, and mass assignment. Do not report dependency CVEs, style notes, generic
   best practices, speculation, or config-leak-only risks.
3. **Fail loud, never report failure as clean.** A failed, rate-limited, blank,
   malformed, or unparsable model call is a failed review step, not zero findings.
   Diff Review must surface the error. Repo Review must count failed unit reviews,
   preserve candidates when verification cannot complete, and avoid marking incomplete
   work as complete.
4. **PoC verification is safe and human-in-the-loop.** Repo Review PoCs run only
   against sandbox or dev environments. Ask the operator for credentials and test data.
   Never use production systems, real credentials, or destructive actions without
   explicit approval.
5. **English only.** Repo code, comments, docs, prompts, and data are English only.
6. **No proprietary content.** The project is public on GitHub and PyPI. Do not add
   internal, confidential, or proprietary code or data.

## Architecture Map

### Diff Review

- Lives under `codejury/review/diff/`.
- `audit_diff` chunks large diffs, runs the selected engine, normalizes categories, and
  applies the deterministic false-positive filter.
- `AuditRunner` is the standard single-call engine.
- `AdversarialAuditRunner` runs Finder, Challenger, and Judge passes for higher recall.
- Findings use `codejury/finding.py` and render through `codejury/report.py`.

### Repo Review

- Lives under `codejury/review/repo/` with playbook assets in `codejury/playbook/`.
- `scaffold.py` builds the workspace, stack notes, candidate files, unit files, and
  methodology assets.
- `model.py` builds a language-agnostic repository file map from data-driven detection
  config and guide globs.
- `engine.py`, `pass_loop.py`, `union.py`, and `verifier.py` own the coded `--run`,
  `--finalize`, resume, dedup, verification, and gate-facing output.
- Agents or model-backed reviewers provide per-unit security judgment. Code owns
  determinism, coverage bookkeeping, and failure accounting.

### Knowledge And Detection

- Vulnerability classes live in `codejury/knowledge/vulnerabilities/`.
- Language, framework, and protocol guides live in `codejury/knowledge/guides/`.
- Source extensions, manifests, noise directories, and test conventions live in
  `codejury/detection.yaml`.
- Framework guides belong under their language, for example
  `knowledge/guides/frameworks/python/django.md`, and declare `language:` in
  frontmatter.

### Providers And Integrations

- Providers live in `codejury/providers/`: Anthropic, OpenAI, LiteLLM, mock, and retry.
- JSON extraction lives in `codejury/json_parse.py`.
- The CLI entry point is `codejury.cli:main`.
- `install-slash-command` copies `playbook/slash-command.md` into the selected agent's
  command directory.

## Agent Workflow

- Read nearby code and tests before changing behavior.
- Keep changes scoped to the requested behavior and the surrounding module boundaries.
- Prefer existing helper APIs and local patterns over new abstractions.
- Do not move security knowledge from markdown data into Python logic.
- When changing model-call handling, preserve fail-loud semantics.
- When changing Repo Review, think through scaffold, run, resume, finalize,
  verification, gate, and tests as one workflow.
- When changing output formats, keep text, markdown, JSON, SARIF, and severity gates in
  sync.
- Do not delete or overwrite user changes. If the worktree is dirty, work around
  unrelated changes and mention relevant conflicts.

## Commands

- Run tests in a venv:
  `python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]" && pytest`
- Diff Review:
  `codejury review diff --file changes.diff`
- Repo Review scaffold:
  `codejury review repo <dir>`
- Repo Review coded run:
  `codejury review repo <dir> --run`
- Repo Review finalize:
  `codejury review repo <dir> --finalize`
- Repo Review gate:
  `codejury review repo <dir> --gate`
- Install slash command:
  `codejury install-slash-command --agent claude|codex`
- Provider configuration comes from flags or environment:
  `CODEJURY_API_BASE`, `CODEJURY_API_KEY`, `CODEJURY_MODEL`
- The tool does not auto-load `.env`.

## Contributing Rules

- Add a vulnerability class by adding `knowledge/vulnerabilities/<id>.md` with
  frontmatter for title, impact, tags, and triggers, plus vulnerable and secure
  examples.
- Add a language, framework, or protocol guide under `knowledge/guides/` with detection
  signals, entrypoint markers, logic-layer globs, and review guidance.
- Add or update tests when behavior changes, especially for failure handling, parsing,
  filtering, gates, and report formats.
- Release by bumping `pyproject.toml`, creating a GitHub Release `vX.Y.Z`, and relying
  on OIDC Trusted Publishing to push to PyPI.

## Style Guide

A tight prose and code style, mirrored from the maintainer's checklist and
enforced, so match it.

Prose, in comments, docstrings, and markdown:

- No em-dash, neither the unicode em-dash nor a spaced double hyphen. Use two sentences, a comma, or a colon.
- No semicolons. Use a period or a comma.
- No parentheses. Reword the aside with "such as", "for example", or a comma.
- Few hyphenated words. Keep the hyphen only where it is part of an identifier, a CLI flag like `--git-range`, a rule id like `sql-injection`, or a file path.
- No sentence begins with the lowercase brand. Start with "It", "The tool", or a rewording.
- Title Case headings. Name the two paths "Diff Review" and "Repo Review" in headings, lowercase "diff review" and "whole-repo review" in running text.
- English only, no CJK, see invariant 5.

Semicolons and parentheses stay where they are code, not prose: code fences, inline code, rule trigger tokens, a method reference like `complete()`, and the prompt strings sent to the model.

Code:

- One statement per line, no `;` separator.
- No linter or type-checker suppression comments. Fix the cause instead, narrow a type with `isinstance` or turn an unreachable line into a real guard.
- A comment earns its place only as the why or an invariant. Delete one that restates the code or narrates history.
- Module names are plural for a collection and singular for one concept, a single word where one reads cleanly.

Commit messages are `type: summary` in the present tense, with few parentheses.

## Detection Quality

- Measure detection quality on real diffs. Synthetic golden sets are not the main signal.
- Model choice dominates detection quality, then mode. Default to standard mode with a
  strong model.
- Use adversarial mode for extra recall on subtle cross-file logic, not as a
  false-positive reducer.
- Keep false positives down with the do-not-report guidance, deterministic filters, and
  verification, not by weakening the finding criteria.
