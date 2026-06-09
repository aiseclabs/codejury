# AGENTS.md

An AI code security review tool. Two paths matched to their nature: a
coded **diff-audit engine** and a fan-out **whole-repo review** where code owns
the orchestration and an agent does the per-unit depth. This is the project's
agent instructions, loaded every session and taking precedence over default
behavior. Claude Code reads it via the `@AGENTS.md` import in `CLAUDE.md`.

## Invariants, Never Violate

1. **Knowledge is rich vulnerability classes, in data.** Security knowledge lives in
   `codejury/knowledge/vulnerabilities/*.md`, with rich per-language vulnerable and secure examples, and
   in the prompts that reference them, not hardcoded in Python. The agent
   methodology lives in `codejury/playbook/methodology.md`. Detection *logic* is generic,
   *what* to detect is data, reviewable in a PR. Knowledge is split by axis and
   stays decoupled: vulnerability classes name the weakness, languages and frameworks carry the
   concrete idioms and the entrypoint markers, and protocols and the methodology
   stay language-neutral. The per-stack guides live under `knowledge/guides/`. A
   framework belongs to a language, so it lives under that language, for example
   `knowledge/guides/frameworks/python/django.md`, and declares
   `language:` in its frontmatter as the source of truth. Adding a language or
   framework is a drop-in guide, no code change. The implementation outside the
   content directories names no specific language or framework: even the source-extension,
   manifest, noise-dir, and test conventions live in `codejury/detection.yaml`, so
   the code stays a generic engine.
2. **Findings are real and evidenced.** Report only real, exploitable,
   high-confidence problems, each with a file location and a concrete exploit
   scenario. No location means not reportable.
3. **Sharp scope, low noise.** Hunt high-impact classes such as business logic, authz /
   IDOR, signature flaws, state bypass / replay, auth bypass, injection, mass
   assignment. Do **not** report dependency CVEs, style or best-practice notes,
   speculative issues with no concrete exploit, or config-leak-only risks.
4. **Two paths, matched to nature.** Diff review is coded, a single LLM call or the
   adversarial Finder/Challenger/Judge pass. Whole-repo review is recall-first and
   too large for a single call, so it fans out: code owns the orchestration, the
   unit worklist, the multi-pass union, the dedup, the adversarial verification, and
   the completeness gate, while the per-unit deep review, where judgment is needed,
   is done by an agent. The `/codejury-review-repo` slash command drives that fan-out
   interactively in a session, which keeps PoC verification human-in-the-loop, and
   `review repo --run` and `--finalize` drive the coded parts headless. The agent
   does the reviewing, the code owns determinism and coverage.
5. **PoC verification is human-in-the-loop and safe.** The repo-review agent
   confirms an issue with a real PoC against a sandbox/dev environment, asking the
   operator for credentials/test-data. It never touches production or real
   credentials and never runs a destructive action without explicit go-ahead.
6. **English only.** All repo code, comments, docs, and data are English, no CJK.
7. **No proprietary content.** This repo is public on PyPI/GitHub. Never put
   internal/proprietary code or data into it.
8. **Fail loud, never report a failure as clean.** A failed, rate-limited, or blank
   model call is a failure, not an empty result. The code raises or counts it and
   keeps the finding, it never turns a failed call into zero findings, because for a
   security tool a silent failure is a hidden miss. Owned by code: the diff path
   surfaces the error, the repo path counts failed unit reviews and keeps a finding
   when verification cannot complete.

## Architecture

| Layer | Implementation | Location |
|---|---|---|
| Diff engine | standard `AuditRunner` for one call plus adversarial `AdversarialAuditRunner` Finder/Challenger/Judge, and `audit_diff` orchestration to chunk, normalize, and filter | `codejury/review/diff/`, `review/diff/runner.py` |
| Vulnerabilities | rich AppSec markdown, trigger-selected and injected into the prompt | `codejury/knowledge/vulnerabilities/`, `review/diff/vulnerabilities.py` |
| Finding + report | flat `Finding`, text/markdown/json/sarif + severity gate | `codejury/finding.py`, `codejury/report.py` |
| Repo review | agent methodology + workspace scaffold, no pipeline | `codejury/playbook/`, `review/repo/scaffold.py` |
| RepoModel | language-agnostic file map, flags candidate entrypoint files via guide globs | `codejury/review/repo/model.py` |
| Detection config | what counts as a source file, a manifest, a noise dir, or test code, across ecosystems, so the code enumerates no language | `codejury/detection.yaml`, `codejury/detection.py` |
| Provider | anthropic · openai · litellm · mock with retry, via a factory | `codejury/providers/` |
| JSON parsing | best-effort extraction of a JSON object from model output | `codejury/json_parse.py` |

## Commands

One verb `review`, split by scope. `review diff` audits a unified diff via
`--file`, `--repo --git-range`, or stdin, with `--mode {standard,adversarial}`.
`review repo <dir>` scaffolds the fan-out workspace, writes the methodology to
`<workspace>/METHODOLOGY.md`, and seeds the per-unit worklist. The interactive path
is the `/codejury-review-repo` slash command: the agent scaffolds then fans out one
deep sub-review per unit following `METHODOLOGY.md`, which keeps PoC verification
human-in-the-loop. The coded steps that need no judgment are commands: `review repo
<dir> --finalize` dedups the findings and adversarially verifies each survivor with
a recall-safe skeptic that refutes only what it can prove safe, and `review repo
<dir> --run` drives the whole fan-out in code for a headless or CI run. `review repo
<dir> --gate` checks the existing workspace against the Completeness Gate, the
surface enumerated, every unit reviewed, every finding graded by the rubric, and
exits non-zero listing each unmet item. All three resume across sessions.
The slash command ships as package data in `playbook/command.md`, and `codejury
install-slash-command [--agent claude|codex]` copies it into the agent's command
directory so a pip install can use it. The body is portable, only the directory
differs, and the review itself is agent neutral. `codejury --version` prints the version.
Shared `review diff` flags: `--provider {anthropic,openai,litellm}`, `--model`,
`--format {text,markdown,json,sarif}`, `--fail-on {critical,high,medium,low}`,
`--no-filter`, `--exclude PATH` repeatable, `--dry-run` for a mock provider with no
key and a built in demo diff when none is supplied.

## Conventions

- Tests run in a venv: `python -m venv .venv && . .venv/bin/activate && pip
  install -e ".[dev]" && pytest`.
- Provider keys come from the environment or flags `CODEJURY_API_BASE`,
  `CODEJURY_API_KEY`, `CODEJURY_MODEL`. The tool does NOT auto-load `.env`.
- Content ships via `[tool.setuptools.package-data] codejury = ["knowledge/**/*.md",
  "playbook/**/*.md", "detection.yaml"]`.
- Add a vulnerability class by dropping a new `knowledge/vulnerabilities/<class>.md` with frontmatter of title,
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
