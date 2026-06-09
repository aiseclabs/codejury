# Playbook Markdown Review

Reviewed every line of all markdown files under `codejury/playbook/`:

- `false-positive-traps.md`, 78 lines
- `methodology.md`, 219 lines
- `severity-rubric.md`, 57 lines
- `slash-command.md`, 103 lines
- `unit-review.md`, 73 lines

No source playbook files were modified.

## Executive Summary

All five markdown files have a reasonable reason to exist. They map to distinct product surfaces:

- `methodology.md`: full interactive repo-review process.
- `unit-review.md`: per-unit mandate embedded into generated unit files and reviewer prompts.
- `severity-rubric.md`: shared grading standard.
- `false-positive-traps.md`: verifier and agent refutation guidance.
- `slash-command.md`: installable prompt body for `/codejury-review-repo`.

The biggest issues are not file existence or naming. The main problems are content consistency and portability:

1. `methodology.md` has a PoC requirement that conflicts with `unit-review.md` and the rest of the methodology.
2. `slash-command.md` is not fully portable across Claude and Codex because it uses Claude-specific orchestration language and hardcodes `--reviewer claude-cli`.
3. Resume language in `methodology.md` and `slash-command.md` is too strong. It says interruptions cost nothing and reviewed units are skipped, but this can preserve partial or failed work if status was marked incorrectly.
4. Style is forceful but uneven. Heavy uppercase words, repeated recall-first paragraphs, and mixed heading levels make the playbook feel less polished than the code.

## Existence And File Boundaries

### `methodology.md`

Keep it. It is the full human/agent methodology and is referenced by scaffold and tests.

The file is long, but its purpose is distinct from `unit-review.md`: it explains the whole workflow, not only one unit. The main optimization is not deletion, but reducing duplicated text that already lives in `unit-review.md`, `severity-rubric.md`, and `false-positive-traps.md`.

### `unit-review.md`

Keep it. This is the per-unit mandate and is embedded into generated unit files and reviewer prompts.

It should probably gain an H1 heading. It currently starts directly with an instruction at line 1, unlike the other playbook files. A title such as `# Unit Review Mandate` would make the file easier to inspect and style-consistent.

### `severity-rubric.md`

Keep it. It is compact and has a clear single purpose.

This is the cleanest file in the directory. It has some repeated recall-first language, but most of it is justified because severity handling is a product invariant.

### `false-positive-traps.md`

Keep it. It is a useful checklist for the verifier and for agent review.

The file is mostly well-scoped. It could use a slightly less dramatic last section title and less uppercase emphasis, but the content is operationally useful.

### `slash-command.md`

Keep it. It is a distinct installable artifact and should not be folded into `methodology.md`.

It does need a portability pass. The project installs it for both Claude and Codex, but the wording and command choice are more Claude-specific than the README suggests.

## Filename Review

Current names are mostly reasonable.

- `methodology.md`: acceptable, though `repo-review-methodology.md` would be clearer outside this directory. Existing code and tests expect `methodology.md`, so renaming has churn.
- `unit-review.md`: good. It names the embedded mandate accurately.
- `severity-rubric.md`: good.
- `false-positive-traps.md`: acceptable. A more neutral name like `verification-traps.md` might better reflect that it covers both false positives and false refutations, but the current name is understandable.
- `slash-command.md`: acceptable as a packaged source file, but generic. Since it installs as `codejury-review-repo.md`, `review-repo-slash-command.md` would be clearer if a rename were worth the code/test churn.

Recommendation: do not rename now unless doing a broader cleanup. The references are centralized in `codejury/resources.py`, but tests and docs also mention these files.

## Serious Content Issues

### 1. PoC guidance conflicts across files

`unit-review.md` says a real finding should still be reported when a PoC cannot be run:

- `unit-review.md:55-58`: write a runnable PoC when possible, but lack of a PoC lowers confidence and does not drop a real finding.

`methodology.md` says the opposite:

- `methodology.md:190-191`: if a concrete runnable PoC cannot be written, the finding is most likely a guess and should not be reported.

This is the most important content problem in the playbook. It conflicts with the human-in-the-loop verification model and with `methodology.md:197-201`, which says runtime facts should become `blocked` needs rather than stopping the run.

Suggested direction:

- Replace `methodology.md:190-191` with language aligned to `unit-review.md`.
- Make the rule: a finding needs concrete traced evidence. A runnable PoC strengthens it, but when runtime facts or credentials are unavailable, report it as `blocked` with exact `Needs:`.

### 2. `slash-command.md` is not truly portable across Claude and Codex

The slash command is installed for Claude and Codex, but the body assumes Claude-style Task subagents:

- `slash-command.md:48-50`: launch one sub-review as a Task subagent.
- `slash-command.md:60`: do not review units in the main context.

It also hardcodes Claude CLI for finalize:

- `slash-command.md:70`: `--finalize --reviewer claude-cli`

This may be correct for Claude Code, but it is awkward for Codex. Codex users receiving this prompt may not have Claude CLI available, and "Task subagent" is not the common portable term.

Suggested direction:

- Use agent-neutral wording such as "launch one focused sub-review per unit using the available subagent or task mechanism".
- For finalize, either use `--finalize` with configured provider by default or explain that `--reviewer claude-cli` is only for Claude Code access.
- Consider separate command bodies if Claude and Codex need materially different execution models.

### 3. Resume language is overconfident

Several lines say interruption is effectively free:

- `slash-command.md:23-29`: an interruption costs nothing.
- `methodology.md:215-219`: a re-run skips reviewed units and verified findings.

The resume concept is useful, but the wording is too absolute. It depends on status and verification state being trustworthy. If a unit is marked reviewed after a failed or incomplete review, resume can skip work that should be retried.

Suggested direction:

- Replace "costs nothing" with "preserves completed checkpoints".
- Say resume should continue from trustworthy reviewed units and failed or blocked units must remain visible.
- Add explicit wording that model failures, unparsable output, or incomplete units must not be marked reviewed.

### 4. `methodology.md` duplicates unit-level mandate too much

`methodology.md:123-151` repeats detailed guidance that also appears in `unit-review.md:4-42`.

Some repetition is useful because `methodology.md` is read standalone, but this amount increases drift risk. The PoC conflict above is an example of drift already happening.

Suggested direction:

- Keep a short summary in `methodology.md`.
- Point to the embedded unit mandate for detailed per-unit behavior.
- Keep only details that the orchestrator needs to verify unit outputs.

## Major Style And Consistency Issues

### Heavy uppercase emphasis is inconsistent and noisy

Examples:

- `unit-review.md:16`: EVERY
- `unit-review.md:30`: BOTH
- `unit-review.md:43`: NEVER
- `false-positive-traps.md:48`: EVERY
- `false-positive-traps.md:64`: SAFE
- `false-positive-traps.md:78`: ALL, KEEP
- `slash-command.md:6`: ORCHESTRATOR
- `slash-command.md:48`: EVERY
- `methodology.md:52`: EVERY

The playbook already uses strong imperative language. Uppercase emphasis makes it feel less polished and less consistent with the proposed AGENTS style. Prefer bold or plain text.

Suggested direction:

- Replace most uppercase emphasis with direct wording.
- Keep only rare uppercase in generated prompt-critical spots if testing shows it matters.

### Heading hierarchy is uneven

`methodology.md` starts with one H1, then uses H2 for "Why Fan Out" and "On Start", but phases use H1 again:

- `methodology.md:1`: H1 title
- `methodology.md:48`: H1 Phase 1
- `methodology.md:78`: H1 Phase 2
- `methodology.md:155`: H1 Phase 3
- `methodology.md:195`: H1 Operator Verification
- `methodology.md:213`: H1 Accumulate Across Runs

Suggested direction:

- Keep only the file title as H1.
- Use H2 for phases and major sections.
- Use H3 for subsections such as "Define the Units".

### Terminology around DAO is inconsistent and too implementation-specific

Examples:

- `unit-review.md:5-6`
- `slash-command.md:54`
- `methodology.md:124-125`

The term appears as lowercase `dao`. Elsewhere the prose is mostly polished and generic. Prefer `DAO` if keeping the acronym, or `data access layer` for broader stack coverage.

### Product name style is inconsistent

`slash-command.md` starts with lowercase prose "codejury":

- `slash-command.md:2`
- `slash-command.md:4`
- `slash-command.md:6`
- `slash-command.md:18`
- `slash-command.md:81`

Use `Codejury` for the product in prose and `codejury` only for the CLI command.

### Spelling is not fully consistent

`slash-command.md:77` uses `recognised`. The rest of the project generally reads as US English. Prefer `recognized` for consistency.

## File-Specific Notes

### `unit-review.md`

Strengths:

- Clear per-unit ownership.
- Strong instruction to trace below entrypoints.
- Good emphasis on authorization, replay, concurrency, and trust boundaries.
- Aligns well with the fail-loud and recall-first invariants.

Issues:

- Missing top-level heading.
- Lines 15-22 are useful but dense and may overfit AI/LLM sink language. If this is intentional, consider adding "AI or LLM calls" to vulnerability knowledge or a protocol/guide, not only the unit mandate.
- Lines 43-53 and 60-67 overlap heavily with `severity-rubric.md`.
- Lines 69-73 ask for issue files and PoCs, but the exact issue template only appears in `methodology.md`. Consider including a compact template or pointing to `methodology.md`.

### `methodology.md`

Strengths:

- Strong explanation of why fan-out exists.
- Good separation of Map, Fan Out, Aggregate, Operator Verification, and Accumulate.
- Explicitly covers non-HTTP entrypoints.
- Good operator safety constraints.

Issues:

- PoC rule at lines 190-191 conflicts with other files.
- Phase headings should be H2, not additional H1s.
- Lines 84-88 say the agent does not invent units, then lines 90-100 say it supplements units. The intended distinction is clear but phrasing is brittle. Say "Do not change the depth mandate. Add missing units only to complete the surface."
- Lines 102-104 imply a sub-review can mark reviewed after an evidenced clear. This is fine, but should also say failed or blocked execution must not be marked reviewed.
- Lines 123-151 duplicate `unit-review.md`.
- Lines 215-219 should be less absolute about resume safety.

### `severity-rubric.md`

Strengths:

- Clear severity levels.
- Good concrete examples.
- Correctly separates "real but low impact" from "not real".

Issues:

- Lines 3-7 and 48-57 repeat the same invariant. Consider keeping the short intro and trimming the final paragraph.
- Line 16 says a precondition is "not a discount". This is memorable but slightly awkward. "not a reason to drop the finding" is clearer.
- The rubric is intentionally domain-weighted toward funds, signing, custody, and authentication. That is fine for this project, but if Codejury reviews general apps, consider making "funds/custody" examples rather than the leading CRITICAL definition.

### `false-positive-traps.md`

Strengths:

- Highly actionable for verification.
- Good two-direction framing: avoid false positives and avoid false refutations.
- The lock/transaction guidance is concrete and useful.

Issues:

- Title says false-positive traps, but much of the file is also about false refutations. `Verification Traps` may better match content.
- Lines 61-78 are important but more forceful than the rest. Reduce uppercase emphasis.
- Lines 45-50 have a long sentence with several clauses. Split for readability.

### `slash-command.md`

Strengths:

- Good step-by-step operational flow.
- Useful resume instructions.
- Clear final report expectation.

Issues:

- Not agent-neutral enough for a file installed for Codex and Claude.
- Hardcodes Claude CLI in finalize.
- Repeats much of `methodology.md`, which creates drift risk.
- Lines 43-45 are long and uneven. Split non-HTTP sources and sequence units.
- Lines 52-53 have an awkward line break after `Each`.
- Line 77 uses `recognised`.
- Lines 92-97 are good but should align with the PoC/blocked finding rule after `methodology.md` is fixed.

## Recommended Optimization Plan

1. Fix the PoC contradiction first.
   - Update `methodology.md:190-191`.
   - Make it match `unit-review.md:55-58` and `methodology.md:197-201`.

2. Make `slash-command.md` portable.
   - Remove or qualify Claude-specific "Task subagent" wording.
   - Do not hardcode `--reviewer claude-cli` for all agents.
   - Consider separate Claude and Codex command bodies only if the execution models cannot share one prompt cleanly.

3. Normalize style.
   - Add an H1 to `unit-review.md`.
   - Change phase headings in `methodology.md` to H2.
   - Replace most uppercase emphasis with plain or bold text.
   - Use `Codejury` for the product and `codejury` for the CLI command.
   - Use `DAO` or `data access layer` consistently.
   - Prefer US spelling, including `recognized`.

4. Reduce duplication.
   - Keep `methodology.md` focused on orchestration and workflow.
   - Keep `unit-review.md` as the detailed per-unit mandate.
   - Keep `severity-rubric.md` as the only detailed severity source.
   - Keep `false-positive-traps.md` as the only detailed verifier-trap source.

5. Add tests or snapshots if changing content affects behavior.
   - Existing tests assert terms such as "Agent Methodology", "Why Fan Out", "Accumulate Across Runs", and "Status: reviewed".
   - If content changes alter those anchors, update tests intentionally.

## Bottom Line

The playbook directory is structurally sound. The files all serve real roles, and the names are acceptable. Optimization should focus on content consistency and portability rather than deletion or major renaming.

The highest-value edits are: fix the PoC contradiction, make the slash command agent-neutral, soften overconfident resume wording, add a heading to `unit-review.md`, normalize heading levels, and reduce repeated recall-first paragraphs.
