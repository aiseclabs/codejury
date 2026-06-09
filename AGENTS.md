# AGENTS.md

The project's agent instructions, loaded every session and taking precedence over
default behavior. Claude Code reads it through the `@AGENTS.md` import in `CLAUDE.md`.

An AI code security review tool with two paths matched to their nature. Diff review
is a coded engine, a single balanced LLM call or an adversarial Finder, Challenger,
and Judge pass. Whole-repo review is recall-first and too large for one call, so it
fans out, with code owning the orchestration and an agent doing the per-unit depth.

## Invariants, Never Violate

1. **Knowledge is data, the engine is generic.** Security knowledge lives in
   `codejury/knowledge/` markdown and in the prompts that reference it, never
   hardcoded in Python. Detection logic is generic, what to detect is data,
   reviewable in a PR. The implementation outside the content directories names no
   specific language or framework, so adding a stack or a class is a drop-in file
   with no code change.
2. **Findings are real, evidenced, and sharply scoped.** Report only real,
   exploitable, high-confidence problems, each with a file location and a concrete
   exploit scenario. No location means not reportable. Hunt the high-impact classes,
   business logic, authz and IDOR, signature flaws, state bypass and replay, auth
   bypass, injection, and mass assignment. Do not report dependency CVEs, style or
   best-practice notes, speculation with no concrete exploit, or config-leak-only
   risks.
3. **Fail loud, never report a failure as clean.** A failed, rate-limited, or blank
   model call is a failure, not an empty result. The code raises or counts it and
   keeps the finding, it never turns a failed call into zero findings, because for a
   security tool a silent failure is a hidden miss. The diff path surfaces the error,
   the repo path counts failed unit reviews and keeps a finding when verification
   cannot complete.
4. **PoC verification is safe and human-in-the-loop.** The repo-review agent confirms
   an issue with a real PoC against a sandbox or dev environment, asking the operator
   for credentials and test data. It never touches production or real credentials,
   and never runs a destructive action without explicit go-ahead.
5. **English only.** All repo code, comments, docs, and data are English, no CJK.
6. **No proprietary content.** This repo is public on PyPI and GitHub. Never put
   internal or proprietary code or data into it.

## Architecture

Two paths, matched to nature. Diff review is coded end to end: `audit_diff` chunks
and normalizes the diff, runs the standard `AuditRunner` for one call or the
adversarial `AdversarialAuditRunner` Finder/Challenger/Judge pass, then filters the
result.

Whole-repo review fans out. `review repo` scaffolds a workspace and a per-unit
worklist, then the work splits in two: an agent does the per-unit deep review where
judgment is needed, and code owns everything deterministic, the worklist, the
multi-pass union, the dedup, the adversarial verification, and the completeness gate.
The interactive `/codejury-review-repo` slash command drives the fan-out in a session,
which keeps PoC verification human-in-the-loop. `review repo --run` drives the same
fan-out headless, `--finalize` runs the coded dedup and verification, and `--gate`
checks coverage against the rubric. All resume across sessions. The agent reviews, the
code owns determinism and coverage.

Knowledge is split by axis and stays decoupled. Vulnerability classes name the
weakness, languages and frameworks carry the concrete idioms and the entrypoint
markers, and protocols and the methodology stay language-neutral. A framework belongs
to a language, so it lives under that language, for example
`knowledge/guides/frameworks/python/django.md`, and declares `language:` in its
frontmatter as the source of truth. Even the source-extension, manifest, noise-dir,
and test conventions live in `codejury/detection.yaml`, so the code enumerates no
language.

Where each layer lives, paths relative to `codejury/`:

| Layer | Lives in | Role |
|---|---|---|
| Diff engine | `review/diff/` | the standard `AuditRunner`, or the adversarial Finder/Challenger/Judge pass, with `audit_diff` to chunk, normalize, and filter |
| Vulnerabilities | `knowledge/vulnerabilities/` | rich AppSec markdown, trigger-selected and injected into the prompt |
| Finding and report | `finding.py`, `report.py` | a flat `Finding`, rendered to text, markdown, json, or sarif, with a severity gate |
| Repo review | `playbook/`, `review/repo/scaffold.py` | the agent methodology and the workspace scaffold, no pipeline |
| RepoModel | `review/repo/model.py` | a language-agnostic file map that flags candidate entrypoints via the guide globs |
| Detection config | `detection.yaml`, `detection.py` | what counts as source, a manifest, a noise dir, or test code, across ecosystems |
| Provider | `providers/` | anthropic, openai, litellm, and mock, with retry, via a factory |
| JSON parsing | `json_parse.py` | best-effort extraction of a JSON object from model output |

## Commands

One verb `review`, split by scope. `review diff` audits a unified diff from `--file`,
`--repo --git-range`, or stdin, in `--mode standard` or `adversarial`. `review repo
<dir>` scaffolds the fan-out workspace and drives it with `--run`, `--finalize`, and
`--gate`, described under Architecture. `codejury install-slash-command [--agent
claude|codex]` copies the portable `playbook/slash-command.md` into the agent's
command directory, and `codejury --version` prints the version. Run a command with
`--help` for the full flag set, including the provider, model, format, fail-on, and
exclude flags.

## Contributing

- Tests run in a venv: `python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]" && pytest`.
- Provider keys come from the environment or the flags `CODEJURY_API_BASE`, `CODEJURY_API_KEY`, `CODEJURY_MODEL`. The tool does NOT auto-load `.env`.
- Add a vulnerability class by dropping `knowledge/vulnerabilities/<id>.md` with frontmatter of title, impact, tags, and triggers, and a body of vulnerable and secure examples. Add a language or framework the same way under `knowledge/guides/`. It is data, no code change.
- Release: bump the `pyproject.toml` version, create a GitHub Release `vX.Y.Z`, and OIDC Trusted Publishing pushes to PyPI.

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

- Measure on real diffs, not a synthetic golden set. Real-world detection quality is the only thing that matters.
- The model dominates detection quality, then the mode. On real-diff probes a strong model at the Sonnet tier in standard mode caught every planted vulnerability with near-zero false positives, while a weaker model raised false positives in both modes. Default to standard mode with a strong model. The do-not-report list and the post-filter keep false positives down. Adversarial mode did not lower them over standard and costs about 3x, so reach for it for extra recall on subtle cross-file logic, not as a false-positive reducer.
