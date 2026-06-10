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
  results.py       the score of one review, recall and precision
  scorers/
    match.py       endpoint and category matching
    parse.py       read findings markdown and json into reports
    score.py       match reports against a key and tally the result
  runners/
    repo.py        score a whole-repo review's findings output
    diff.py        run the diff capability probe and score
  diff_cases.py    the shipped synthetic diff cases
  config.py        discover public benchmarks plus private sources
  compare.py       diff two results, the per-issue flips and deltas
  benchmarks/
    repo/<name>/target.yaml      a git pointer, never vendored code
    repo/<name>/answer_key.yaml  planted issues and safe lookalikes
```

An answer key has `planted` issues a complete review must surface and `safe` lookalikes a
report would be a false positive on. The legacy `issues` key is accepted as an alias. The
review under test never reads the key.

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
# 1. review a cloned target, see its target.yaml for the pointer
git clone --depth 1 --branch v0.3.8 https://github.com/open-webui/open-webui /tmp/owui
codejury review repo /tmp/owui/backend/apps/webui --workspace /tmp/cj-owui
#    an agent then follows METHODOLOGY.md, then finalize writes findings/

# 2. score it. Prefer --findings-json, findings/ collapses findings on one endpoint of
#    different classes into a single file, so --findings-dir can undercount the reports
python -m evals repo openwebui --findings-json /tmp/cj-owui/webui/findings.json --json after.json

# 3. compare two versions
python -m evals compare before.json after.json

# diff capability probe, needs provider creds in the environment
python -m evals diff --mode standard --model <id>
```

A benchmark grows by adding more planted issues and lookalikes, or a new `repo/<name>/`
directory with its `target.yaml` and `answer_key.yaml`. Keep public benchmarks public and
non-proprietary, this repo ships to PyPI and GitHub.
