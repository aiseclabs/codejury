# CLAUDE.md

codejury: an Application Security AI audit framework. Domain knowledge lives in
versioned YAML, not in prompts. This file is loaded every session and takes
precedence over default behavior. Strategy and phased plan: see `ROADMAP.md`.

## Invariants (never violate; a change that breaks one is rejected even if `eval` passes)

1. **Knowledge is data.** Security knowledge lives in `codejury/data/`
   (skills as `data/skills/<id>/{skill.yaml, SKILL.md}`, plus suppressions and
   golden), reviewable in a PR, editable by non-engineers. Detection *logic* is
   generic; *what* to detect is data. Do not hardcode vulnerability knowledge in
   prompts or Python.
2. **Determinism & reproducibility.** Same input must give the same verdicts.
   Providers run at temperature 0; verdicts are cached on
   `hash(normalized code + skill fingerprint + orchestration)`; `--no-cache`
   bypasses. (Determinism work is tracked under ROADMAP P0.)
3. **Every finding has evidence.** A Verdict/Finding must carry a code location
   (file + line). No location -> not reportable.
4. **eval is the fitness function.** Detection quality is measured by
   `codejury eval` against the golden set; changes are judged by it.
5. **No self-judging.** An agent must NOT certify the golden set's correctness,
   set eval thresholds, or edit the golden set / scoring logic to make a change
   "pass". Those are human-signed.
6. **English only.** All repo code, comments, docs, and data are English; no CJK.

## Architecture (5 layers; layers talk only through typed data; each is an ABC + impls)

| Layer | Implementations | Location |
|---|---|---|
| Task | YAML presets (skills + orchestrator + provider + model) | `codejury/tasks/`, `codejury/data/tasks/` |
| Skill | 16 skills (11 OWASP ASVS areas + OWASP LLM Top 10 + api_design), each a `skill.yaml` manifest + `SKILL.md` prose playbook | `codejury/data/skills/<id>/` |
| Selector | applies_to filter + temperature-0 model router (which skills to run) | `codejury/selection.py` |
| Orchestrator | single · pipeline · debate · reflexion · challenge · taint · adaptive | `codejury/orchestrators/` |
| Source | mock · diff · function · repo · api_surface (chunker, callers/callees context) | `codejury/sources/` |
| Agent | skill_runner · finder · challenger · judge · refuter · mock | `codejury/agents/` |
| Provider | anthropic · openai · litellm · mock (+ retry wrapper) | `codejury/providers/` |
| Infrastructure | json parsing, verdict + selection cache, ... | `codejury/infrastructure/` |

Cross-cutting modules: `assembly.py` (build orchestration + provider factory),
`selection.py`, `analysis/` (provenance/taint + RepoModel), `reporting.py`,
`evaluation.py`, `suppression.py`, `resources.py`, `cli.py`,
`integrations/github.py`.

## Commands

`dry-run` (mock, no key) · `audit [diff]` · `scan <dir>` · `run <task>` · `eval`.
Shared flags: `--orchestrator {single,pipeline,debate,reflexion,challenge,taint,adaptive}`,
`--provider {anthropic,openai,litellm}`, `--model`,
`--format {text,markdown,json,sarif}`, `--fail-on {critical,high,medium,low}`.

## Conventions

- Tests run in a venv (system python is PEP 668 externally-managed):
  `python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]" && pytest`.
- Provider keys come from the environment (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
  or generic `CODEJURY_API_BASE` / `CODEJURY_API_KEY` / `CODEJURY_MODEL`).
  codejury does NOT auto-load `.env`; `source` it.
- Data ships via `[tool.setuptools.package-data] codejury = ["data/**/*.yaml", "data/**/*.md"]`.
- Skill ids (`authn`, `authz`, `input_validation`, ...) are what `--only`
  and a task's `skills:` accept.
- Release: bump `pyproject.toml` version -> GitHub Release `vX.Y.Z` -> OIDC
  Trusted Publishing pushes to PyPI (no token stored).

## Boundaries

- Never put proprietary/internal code (e.g. Cobo source) into the repo or golden
  set: this repo is public on PyPI/GitHub.
- Taint-class precision (path traversal, SSRF) has a known LLM single-file-review
  floor (see ROADMAP). Do not grind verifier prompts to fix it; the real path
  is static data-flow analysis (P1).
