# AGENTS.md

Project instructions for coding agents. Codex reads `AGENTS.md` directly. Claude Code
reads it through the `@AGENTS.md` import in `CLAUDE.md`.

An AI-assisted security review tool for code diffs and whole repositories. Diff Review
is the coded path. Repo Review is the fan-out path where code owns the deterministic
orchestration and agents or model calls provide per-unit judgment.

## Non-Negotiable Invariants

1. **Knowledge is data, the engine is generic.** Security knowledge belongs in each
   domain's `knowledge/` markdown under `codejury/domains/<domain>/` and in prompts that
   reference it. Do not hardcode language, framework, or vulnerability-specific detection
   logic in Python. Adding a stack or vulnerability class should usually be a data change.
2. **Recall is the first red line.** The priority order is recall, then false-positive
   rate, then blind-run stability. A missed real, exploitable issue is the worst
   outcome. A stage after the finder, such as dedup or verification, deletes a candidate
   only on a controlling fact it can read, never on an assumed off-file control.
3. **Findings are real, evidenced, and scoped.** Report only exploitable,
   high-confidence issues with a concrete file location and exploit scenario. No
   location means not reportable. Prioritize high-impact classes such as business
   logic, authorization, IDOR, signature flaws, replay, authentication bypass,
   injection, and mass assignment. Do not report dependency CVEs, style notes, generic
   best practices, speculation, or config-leak-only risks.
4. **Fail loud, never report failure as clean.** A failed, rate-limited, blank,
   malformed, or unparsable model call is a failed review step, not zero findings.
   Diff Review must surface the error. Repo Review must count failed unit reviews,
   preserve candidates when verification cannot complete, and avoid marking incomplete
   work as complete.
5. **Improve the general case, never fit the benchmark.** A change to knowledge,
   prompts, or code earns its place only if it would be written without having seen the
   answer key. Do not encode a benchmark's specific findings, sink names, case
   variables, or fix shapes. Validate a change on a target it was not derived from, the
   benchmark it came from can only sanity-check, never prove. Never adjust a scorer or
   an answer key to raise a score.
6. **PoC verification is safe and human-in-the-loop.** Repo Review PoCs run only
   against sandbox or dev environments. Ask the operator for credentials and test data.
   Never use production systems, real credentials, or destructive actions without
   explicit approval.
7. **English only.** Repo code, comments, docs, prompts, and data are English only.
8. **No proprietary content.** The project is public on GitHub and PyPI. Do not add
   internal, confidential, or proprietary code or data.

## Architecture Map

### Domains

- A domain bundles one body of security knowledge under its own content root,
  `codejury/domains/<name>/`, holding `knowledge/`, `playbook/`, and `detection.yaml`.
- `domains/base.py` defines `Domain`, the `ContentPaths` layout resolver, and the
  optional `FactsBackend` and `SourceLoader` seams. It imports nothing from `codejury`,
  so leaf modules depend on it with no import cycle.
- `domains/registry.py` is the one place that lists the domains. `web` is the default,
  `evm` reviews Solidity smart contracts. `resolve_domain` maps a `--domain` choice or
  `auto` detection to a `Domain`.
- The engine reads knowledge, pass lenses, and the diff prompt blocks from the selected
  domain, so a new domain is a content directory plus a registry entry, not an engine
  change.
- `codejury/resources.py` exposes the web domain's paths as the default constants the
  Diff Review path reads when no domain is selected.

### Diff Review

- Lives under `codejury/review/diff/`.
- `audit_diff` chunks large diffs, runs the selected engine, normalizes categories, and
  applies the deterministic false-positive filter.
- `AuditRunner` is the standard single-call engine.
- `AdversarialAuditRunner` runs Finder, Challenger, and Judge passes for higher recall.
- Findings use `codejury/finding.py` and render through `codejury/report.py`.

### Repo Review

- Lives under `codejury/review/repo/` with playbook assets in each domain's `playbook/`.
- `scaffold.py` builds the workspace, stack notes, candidate files, unit files, and
  methodology assets.
- `model.py` builds a language-agnostic repository file map from data-driven detection
  config and guide globs.
- `engine.py`, `pass_loop.py`, `union.py`, and `verifier.py` own the coded `--run`,
  `--finalize`, resume, dedup, verification, and gate-facing output.
- Agents or model-backed reviewers provide per-unit security judgment. Code owns
  determinism, coverage bookkeeping, and failure accounting.

### Knowledge and Detection

- Vulnerability classes live in `codejury/domains/<domain>/knowledge/vulnerabilities/`.
- Language, framework, and protocol guides live in
  `codejury/domains/<domain>/knowledge/guides/`.
- Framework guides belong under their language, for example
  `domains/web/knowledge/guides/frameworks/python/django.md`, and declare `language:` in
  frontmatter.
- Source extensions, manifests, noise directories, and test conventions live in each
  domain's `detection.yaml`, for example `codejury/domains/web/detection.yaml`.
- The evm domain adds an optional `facts/` package, a Slither call-graph backend and a
  Forge PoC seam, behind the `codejury[evm]` extra.

### Providers and Integrations

- Providers live in `codejury/providers/`: Anthropic, OpenAI, LiteLLM, mock, retry, and the
  `claude_agent` subscription transport. `claude_agent` holds the shared `claude -p` runner and
  `ClaudeAgentProvider`, the keyless backend both review paths use, see invariant 6 and the
  `--executor` seat resolution in the CLI.
- JSON extraction lives in `codejury/json_parse.py`.
- The CLI entry point is `codejury.cli:main`.
- `install-slash-command` copies the selected domain's `playbook/slash-command.md` into
  the selected agent's command directory.

## Agent Workflow

- Read nearby code and tests before changing behavior.
- Keep changes scoped to the requested behavior and the surrounding module boundaries.
- Prefer existing helper APIs and local patterns over new abstractions.
- When changing model-call handling, preserve fail-loud semantics.
- When changing Repo Review, think through scaffold, run, resume, finalize,
  verification, gate, and tests as one workflow.
- When changing output formats, keep text, markdown, JSON, SARIF, and severity gates in
  sync.
- Do not move security knowledge from markdown data into Python logic.
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
- Provider configuration comes from flags or environment, not an auto-loaded `.env`:
  `CODEJURY_MODEL`, `CODEJURY_API_KEY`, `CODEJURY_API_BASE`

## Contributing Rules

- Add a vulnerability class by adding
  `domains/<domain>/knowledge/vulnerabilities/<id>.md` with frontmatter for title,
  impact, tags, and triggers, plus vulnerable and secure examples.
- Add a language, framework, or protocol guide under
  `domains/<domain>/knowledge/guides/` with detection signals, entrypoint markers,
  logic-layer globs, and review guidance.
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
- English only, no CJK, see invariant 7.

Semicolons and parentheses stay where they are code, not prose: code fences, inline code, rule trigger tokens, a method reference like `complete()`, and the prompt strings sent to the model.

Code:

- One statement per line, no `;` separator.
- No linter or type-checker suppression comments. Fix the cause instead, narrow a type with `isinstance` or turn an unreachable line into a real guard.
- A comment earns its place only as the why or an invariant. Delete one that restates the code or narrates history. A docstring states the why in one line, it does not narrate what the next line of code plainly does. A test needs no comment that repeats its own name.
- Module names are plural for a collection and singular for one concept, a single word where one reads cleanly.

Commit messages are a single `type: summary` line in the present tense, with few
parentheses. No body and no trailers, so no `Co-Authored-By` or other trailer line.

## Detection Quality

- Measure detection quality on real diffs. Synthetic golden sets are not the main signal.
- Pick the model first, it dominates detection quality, mode comes second. Default to
  standard mode with a strong model.
- Use adversarial mode for extra recall on subtle cross-file logic, not as a
  false-positive reducer.
- Keep false positives down with the do-not-report guidance, deterministic filters, and
  verification, not by weakening the finding criteria.
