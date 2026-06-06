# codejury Design v2

The foundational redesign of the whole-repo review path. Companion to `ROADMAP.md`,
the strategy, and `CLAUDE.md`, the invariants. This is the built and validated
design: the fan-out path is implemented under `codejury/review/repo/`, and the
direction is proven on the real baseline, real-A moved from 2 of 8 cold to 8 of
8 confirmed, with the one known false positive correctly refuted.

## The failure this fixes, measured

A fresh whole-repo review, run cold the way a user actually invokes it, finds only
a quarter of the real issues in a real codebase. Measured, not asserted:

| Target | Scale | Recall, single cold run |
|---|---|---|
| custody (synthetic) | 8 files, 750 LOC | 5/5 |
| custodyx (synthetic) | 31 files, 750 LOC | 8/8 |
| real-B | tens of thousands of LOC | ~3 of 7 |
| real-A | ~30k LOC first party | 2 of 8 known real findings |

The only variable that moves recall is scale. Same cold start, same model, no
priming: a small target is fully covered in one pass, a real one is not. The
official real-A review reached 8/8 only as the union of many independent runs
plus human adjudication, which is manual brute force, not what a single invocation
does.

This is the original complaint, reproduced and quantified: on a real repo a single
review pass recovers about 25 percent of what is there.

### The fix, measured

The fan-out path closes the gap on the same target, same model, no priming:

| Target | Recall, single cold run | Recall, fan-out v2 |
|---|---|---|
| real-A | 2 of 8 | 8 of 8, with the 1 known false positive refuted |

8 of 8 is now what one invocation does, structurally, not what many hand-run passes
plus human adjudication reach. The coded verify stage refuted the one real false
positive (a redeem race whose `select_for_update` holds the row lock inside
`transaction.atomic`) while keeping every real finding, the recall-and-precision
result the redesign was for.

## Root cause

One serial agent reading a whole large repo dilutes. Its attention is spread across
the entire surface, so each endpoint gets a shallow look, and the deep cross-file
flaws below the entrypoint are missed. The methodology compensates with the recall
union, run the whole review many times and take the union, which is exactly an
admission that one pass is too shallow. The forcing functions, the ledgers and
sweeps and gates, make the single pass produce more bookkeeping, not more depth.

So the leverage was in the wrong place. The earlier diagnosis stands: the
methodology under grounds the agent and under decomposes the search, and pours its
budget into policing diligence instead. More policing cannot fix a shallow pass at
scale.

## First principles

1. **One north star, two operating points.** Detection quality is the only first
   class metric, measured on real targets. The diff path is a CI gate, fast and
   precision first. The repo path is a deep audit, recall first, multi pass, human
   in the loop for a PoC. They share knowledge, not control flow.
2. **The architecture is a trust allocation.** The model owns the reasoning, it
   cannot be trusted to be complete or honest. The code owns the guarantees the
   model cannot give: determinism, honesty, auditability, scope. The data owns the
   domain knowledge so a human can audit what we look for. The agent owns the
   orchestration a single trusted call cannot reach, and the human gate.
3. **codejury occupies the complement of deterministic SAST.** It targets the
   classes that need reasoning across files and context: authorization, IDOR,
   business logic, replay, state bypass. So it has no deterministic detection core
   by design.
4. **Never report a failure as clean. Owned by code.** A failed or blank model
   reply is a failure, never an empty result.
5. **Knowledge is data, on both paths.** One body of knowledge, consumed by the
   diff engine and the repo methodology alike.
6. **Eval is the instrument, not a side script.** This redesign exists because a
   gauge finally showed the real number, 2 of 8 on a real repo. Every change is
   judged by that gauge moving, not by the completeness gate turning green.

## Repo review v2

The shift: from one serial agent skimming the whole repo, to enumerate, decompose,
fan out, aggregate. Recall comes from focus and parallelism, the way the official
review reached 8/8 by hand, made into the structure of the methodology itself. It
stays agent driven, the methodology directs the agent to fan out, it is not a coded
pipeline.

### A. Build the model, ground the coverage denominator

The agent first builds three persistent artifacts in the workspace: the attack
surface inventory, the authorization model with its trust boundaries, and the
sensitive data map. The inventory is the denominator: a real repo has 100+
endpoints, and a single pass never enumerates them all, so coverage must be counted
against a built inventory, not against what the agent happened to notice.

Grounding the inventory is invariant safe, the code names no language. Structure is
sourced along a fallback ladder where the language specific part is data the guide
declares: agent plus grep on the guide markers, then a generic tree-sitter runner
with the per language query in the guide, then a framework route lister the guide
names. The ladder rung is chosen by a bake-off measured against ground truth.

### B. Decompose into units

From the inventory, derive the worklist of units: one per endpoint, or per small
group of sibling endpoints behind a controller. A unit is small enough that one
focused investigation reasons about it deeply, traces it into the managers, dao,
and controllers it reaches, and challenges its controls, without the dilution of
holding the whole repo.

### C. Fan out, investigate each unit deeply, verify in place

Each unit is a focused sub review: form the hypothesis, trace the real code for that
unit to its sink, then adversarially refute in the same step, name the controlling
fact, attack it, run a PoC when the harness needs no operator input. Units are
independent, so they run in parallel. This is what replaces the recall union: the
fan out is the union, done once, structurally, with each unit getting full attention
instead of a share of one pass.

Verification lives inside the unit, so a stateful refute must run against an
environment that models production, not a SQLite no-op, which is the precision trap
that produced the one real false positive on real-A.

### D. Aggregate and derive coverage

Coverage is the units with a verdict over the units in the inventory. The
denominator comes from A and every unit carries a verdict with evidence, so
completeness is grounded and cannot be faked by filling a table. The gate becomes
one check against the artifacts: every unit in the inventory has a verdict with
evidence.

### E. Finalize in code, the precision counterweight

The fan-out maximizes recall by surfacing everything across diverse passes, which
also lets bounded-but-real-looking misreads through. A coded `--finalize` stage is
the precision counterweight that earns the right to surface everything, and it is
code, not prose, so it always runs: it dedups candidates by location and class,
hands each survivor to an independent skeptic that traces across files and judges
against production semantics, drops the refuted with a named controlling fact into
`_refuted.md`, and writes the ranked `findings.json`. The skeptic is recall-safe,
it refutes only when a controlling fact makes the code genuinely safe, never for low
impact or idempotency, and must rule out every harm path, so it kills the real false
positive without dropping a real finding.

### As built: backends and resumability

Two things the design did not name but the build needed. The per-unit review and
the per-candidate verification are pluggable backends: a grounded model call, or a
headless `claude -p` agent that reads the files itself, which uses the operator's
Claude Code access instead of a rate-limited proxy and gives each call real
tool-using depth. And every stage is resumable across sessions, a reviewed unit and
a verified finding are skipped on re-run, so a usage limit costs nothing and the
review survives the session cap a real-repo audit will hit.

### What gets deleted

The recall union as the primary mechanism, replaced by the fan out. The standalone
negatives ledger, folded into each unit's intrinsic refutation. The four standalone
sweep tables and the table-counting gate, replaced by per unit coverage derived from
the inventory. Most of the prose policing in the methodology, which shrinks to the
process skeleton of A through D plus the autonomy and human in the loop rules.

## Knowledge unification

The real security knowledge moves out of code and prose into reviewable data. The
false-positive and over-refutation traps, including the lock-and-transaction
semantics and the recall-first refutation rules, live in
`playbook/false-positive-traps.md` as the single source, loaded by both the model
and the agent verifier, so the same knowledge is not hardcoded in two prompts. The
vulnerability class shapes stay in `knowledge/vulnerabilities/`, per class and per
language. Both paths consume the data, the code names none of it.

## Eval

The instrument that steers the redesign.

- `validation/probe.py` is the diff path probe, fixed.
- `validation/repo/` is the repo path ruler: `score.py` matches reported findings to
  an answer key by endpoint and prints recall and precision. Targets are authored
  fixtures under `targets/`, or pointers to real public repos under `targets/<name>/SOURCE.md`.
- The real baseline to beat is real-A at 2 of 8, run cold and single pass. The
  fan out is judged by whether it lifts that number, on the same target, same model,
  no priming. The real targets are proprietary, they stay local, nothing of them
  enters this repo.

## Phased plan

Each phase is independent and reviewable. The author commits, the assistant writes
to the review point and stops.

0. **Ruler and baseline.** Done. The repo eval exists, and the honest baseline is
   real-A 2/8 cold single pass.
1. **Minimal fan-out prototype.** Done, and the direction is proven: fan-out lifted
   real-A recall from 2/8 to 8/8, so v2 proceeded.
2. **Grounding.** Done. The scaffold builds the attack-surface inventory, the
   authorization model, and the units worklist as workspace artifacts, the coverage
   denominator.
3. **Productize the loop into the methodology.** Done. `methodology.md` and the
   `/codejury-review-repo` slash command direct the agent to enumerate, decompose,
   fan out per unit, and aggregate, with per-unit verification.
4. **Derive coverage, delete the treadmill.** Done. The gate is the per-unit
   coverage check, the recall union as primary mechanism, the negatives ledger, and
   the sweep tables are gone. A coded `--finalize` owns dedup and adversarial verify.
5. **Re-measure, keep the gauge honest.** Ongoing. Recall is re-scored on real-A
   after each change, in a clean room, the auditor blind to the answer key. Next:
   the real-B blind run and a stability re-run.

## Secondary gaps, evidenced but not primary

- **Stateful precision.** A concurrency or lock claim refuted by a PoC against a non
  representative environment gives a false positive, the real-A select_for_update
  on SQLite. Stateful refutation must run against production-like locking.
- **Cross-endpoint business logic.** An invariant that spans a sequence of endpoints,
  the approve then mutate then execute shape, is missed by per endpoint analysis. The
  unit decomposition must include sequence units, not only single endpoints.

## Follow ups, out of scope here

- Sharpen `CLAUDE.md` invariant 1 to state the precise boundary: the code names no
  language, language specific analysis lives in data or the agent runtime.
- Add the fail loud principle as an explicit invariant.
- The diff path code cleanups, the vulnerabilities loader placement, the prompt
  content as data, the runner naming, the CLI dispatch, prompt caching, are separate
  from this redesign.
