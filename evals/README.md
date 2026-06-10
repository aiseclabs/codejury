# Evals: The Detection-Quality Ruler

The gate only checks structural completeness, surface enumerated, units reviewed, findings
graded. Green does not mean the review found real bugs. This is the ruler that does: a
change to the knowledge, prompts, or methodology is judged by recall and precision moving
on real targets, not by the gate.

The engine ships here. The data does not have to. Public OSS benchmarks live in
`benchmarks/`. Private benchmarks stay wherever they already are and plug in through a
local, uncommitted config, so nothing private enters the repo.

## What "Better" Means

A single score cannot tell an improvement from noise, the review is not deterministic. The
standard is a move that holds up under repetition:

1. Control variables. Same target at the same commit, same model, same mode. Vary only the
   code under test.
2. Run several times per version and read the spread, not one number. A change counts only
   when the distributions separate beyond the noise band across runs.
3. Judge recall and precision together across the whole suite, not one target. A change
   that lifts recall by flooding false positives is not an improvement.
4. Read the per-issue flips, which planted issues went missed to found or found to missed,
   they carry more signal than the aggregate. `compare` prints them.

Two tiers, kept honest:

- Public benchmarks here are reproducible regression and smoke checks. They carry a
  leakage caveat, the model may have seen the CVE, so they measure "did not regress" more
  than true recall.
- Private, unseen targets are the real recall signal. They never enter this repo.

## Layout

```
evals/
  schema.py        answer key, key entry, and the normalized report shape
  results.py       the score of one review, and N runs folded by frequency
  scorers/
    match.py       endpoint and category matching
    parse.py       read findings markdown and json into reports
    score.py       match reports against a key and tally the result
  runners/
    repo.py        score a whole-repo review's findings output
    diff.py        run the diff capability probe and score
  diff_cases.py    load the shipped diff cases, engine-free so the matrix can read them
  registry.py      discover benchmarks across public and private sources
  knowledge.py     scan the knowledge tree, build the coverage matrix
  suites.py        a named tag selection over the cases and benchmarks
  compare.py       diff two results, the per-issue flips and deltas
  benchmarks/
    diff/cases.yaml              the shipped synthetic diff cases, each with knowledge
    suites/<name>.yaml           a tag selection, public-smoke and knowledge-coverage
    repo/<name>/benchmark.yaml   a git pointer plus the stack and knowledge it exercises
    repo/<name>/answer_key.yaml  planted issues and safe lookalikes
```

A `benchmark.yaml` is the manifest: the clone pointer, never vendored code, plus the
stack and the knowledge the target exercises, so the coverage matrix can attribute it. The
legacy `target.yaml` carrying only the pointer is still read, so a private benchmark need
not be reshaped.

An answer key has `planted` issues a complete review must surface and `safe` lookalikes a
report would be a false positive on. Each entry may name the knowledge it exercises. The
legacy `issues` key is accepted as an alias. The review under test never reads the key.

## Knowledge Coverage

Knowledge is data and the engine is generic, so a vulnerability class or a guide with no
eval is a gap that should be visible, not silent. `python -m evals coverage` scans the
knowledge tree and crosses it against the registry, counting the positive and safe diff
cases and the repo planted and safe entries that exercise each file, public and private:

```bash
python -m evals coverage
```

It names the uncovered files, the worklist for the case library, and reports the gate
problems: a vulnerability with no positive or no safe diff case, a benchmark reference that
resolves to no real knowledge file, and an answer key entry that names no knowledge. An
unresolved reference is broken benchmark data, so the command exits nonzero on it, while a
missing case is a known gap and exits zero.

## Private Benchmarks, Not Committed

Create a local `evals/local.yaml`, gitignored, or point `CODEJURY_EVAL_CONFIG` at one:

```yaml
benchmark_sources:
  - path: /abs/path/to/your/private/benchmarks   # used where it already lives
  - repo: git@github.com:you/private-benchmarks.git
    ref: main
```

A source root may use the new `repo/<name>/answer_key.yaml` layout or the legacy
`groundtruth/<name>.yaml`, so existing private data scores without being reshaped. Benchmark
names resolve across the public root and every source.

## Run

The repo path does not run the review, the agent or a coded run does that, this scores the
output it wrote.

```bash
# 1. review a cloned target, see its benchmark.yaml for the pointer
git clone --depth 1 --branch v0.3.8 https://github.com/open-webui/open-webui /tmp/owui
codejury review repo /tmp/owui/backend/apps/webui --workspace /tmp/cj-owui
#    an agent then follows METHODOLOGY.md, then finalize writes findings/

# 2. score it. Prefer --findings-json, findings/ collapses findings on one endpoint of
#    different classes into a single file, so --findings-dir can undercount the reports
python -m evals repo openwebui --findings-json /tmp/cj-owui/webui/findings.json --json after.json

# 3. compare two versions
python -m evals compare before.json after.json

# diff capability probe, needs provider creds in the environment. --runs N repeats and
# folds by frequency, so a planted issue counts as caught only by a strict majority of runs
python -m evals diff --mode standard --model <id> --runs 3

# a suite is a tag selection over the library, public-smoke is a fast subset
python -m evals run public-smoke --model <id> --runs 3

# what the registry sees, benchmarks and suites with the cases each selects
python -m evals list
```

Repeated runs are how a change is judged honestly, the review is not deterministic. A single
run is one `Result`, `--runs N` folds N runs into a frequency verdict, found by strict
majority, so one lucky or unlucky run does not move the score and the spread is visible. The
repo path stays score-only, aggregate N agent runs by scoring each and reading the flips.

A benchmark grows by adding more planted issues and lookalikes, or a new `repo/<name>/`
directory with its `benchmark.yaml` and `answer_key.yaml`. The diff probe grows by adding a
row to `benchmarks/diff/cases.yaml`, a positive with a category or a safe lookalike without
one, each naming the knowledge it exercises so `coverage` attributes it. A suite grows by
adding `benchmarks/suites/<name>.yaml` naming the tags it selects, no second list of cases
to keep in sync. Keep public benchmarks public and non-proprietary, this repo ships to PyPI
and GitHub.
