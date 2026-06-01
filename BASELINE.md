# codejury baseline (P0-05)

The first recorded fitness measurement against the golden set. This is the
factual baseline the ROADMAP gates are calibrated from; the gate **thresholds**
themselves are human-signed (CLAUDE.md invariant 5).

## Run

- **Date:** 2026-06-01
- **Version:** 0.5.1
- **Command:** `codejury eval --provider litellm --format json`
- **Provider/model:** LiteLLM proxy, model from `CODEJURY_MODEL` (alias kept out
  of this public repo). Single verifier, temperature 0 (deterministic).
- **Corpus:** 37 golden cases (17 vulnerable / 20 safe); 5 tagged `held-out`.

Reproduce: `source .env && codejury eval --provider litellm --format json`.

## Overall

| cases | TP | FP | TN | FN | precision | recall | F1 | accuracy |
|------:|---:|---:|---:|---:|----------:|-------:|---:|---------:|
| 37 | 15 | 1 | 19 | 2 | 0.94 | 0.88 | 0.91 | 0.92 |

Held-out split (5 cases): 5/5 correct, P/R/F1 = 1.00.

## Per capability

| capability | TP | FP | TN | FN | P | R | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| authn | 2 | 0 | 3 | 0 | 1.00 | 1.00 | 1.00 |
| authz | 1 | 0 | 1 | 0 | 1.00 | 1.00 | 1.00 |
| business_logic | 1 | 0 | 1 | 0 | 1.00 | 1.00 | 1.00 |
| crypto | 1 | 0 | 1 | 0 | 1.00 | 1.00 | 1.00 |
| data_protection | 1 | 0 | 1 | 0 | 1.00 | 1.00 | 1.00 |
| dependency_config | 1 | 1 | 0 | 0 | 0.50 | 1.00 | 0.67 |
| error_logging | 1 | 0 | 1 | 0 | 1.00 | 1.00 | 1.00 |
| input_validation | 4 | 0 | 8 | 2 | 1.00 | 0.67 | 0.80 |
| output_encoding | 1 | 0 | 1 | 0 | 1.00 | 1.00 | 1.00 |
| secrets | 1 | 0 | 1 | 0 | 1.00 | 1.00 | 1.00 |
| session | 1 | 0 | 1 | 0 | 1.00 | 1.00 | 1.00 |

9 of 11 capabilities are perfect. All false-positive-prone negatives passed
(constant-URL SSRF, basename traversal stripping, fixed-argv subprocess,
`json.loads` vs `pickle.loads`, host allowlist); the verifier did not
over-flag them.

## The three errors

| case | capability | label | predicted | type |
|---|---|---|---|---|
| `dependency_config_tls_verify_on_safe` | dependency_config | safe | VULNERABLE | FP |
| `deserialize_pickle_vuln` | input_validation | vuln | safe | FN |
| `ssrf_user_url_vuln` | input_validation | vuln | safe | FN |

- **FP**: `requests.get(..., timeout=10)` with TLS verification at its secure
  default was read as a problem; the verifier is over-cautious about HTTP calls.
- **FN (x2)**: both are taint-class sinks the verifier missed. The likely
  cause is a data gap: the `input_validation` capability YAML does not enumerate
  SSRF or insecure-deserialization anti-patterns, so the model is not primed to
  flag them. This is a capability-data / data-flow gap for P1/P3, not a prompt to
  grind (CLAUDE.md boundaries: taint precision is not fixed by prompt tuning).

## Determinism check

The eval run and an independent per-case re-run produced identical verdicts on
all 37 cases (same one FP, same two FN), consistent with temperature 0.

## Gate status

`Unlock P1` requires the per-capability baseline to be **recorded**, done here.
The P1/P2/P3/P4 acceptance thresholds (X/Y/Z in ROADMAP) remain human-signed and
are filled in only on your sign-off.

## Updates since baseline

The numbers above are frozen as the reference the ROADMAP gates measure against;
improvements are logged here rather than overwriting them.

- **2026-06-01: SSRF + insecure-deserialization anti-patterns added to
  `input_validation.yaml`.** The two baseline false negatives were a knowledge
  gap, not a model limit: the capability did not enumerate those sinks. Adding
  them lifts `input_validation` from P 1.00 / R 0.67 / F1 0.80 to **P 1.00 /
  R 1.00 / F1 1.00**, and overall from F1 0.91 to **0.97** (R 0.88 -> 1.00),
  with no new false positives; all false-positive-prone negatives still pass.
  This clears the signed P1 recall gate **on this single-file corpus**; it does
  not retire the taint floor for real cross-file code, where provenance still
  needs the P1 data-flow engine. The lone remaining error is the
  `dependency_config` TLS false positive.

- **2026-06-01: TLS verification dimension added to `dependency_config.yaml`.**
  The capability had no transport-security dimension, so the verifier judged
  outbound HTTPS calls by generic "unsafe defaults" reasoning, catching
  `verify=False` but also over-flagging the secure-default call. A
  `transport_security` sub-capability (secure-default correct pattern + a
  CWE-295 anti-pattern scoped to *disabling* verification) clears the false
  positive while keeping the true positive. Golden set is now **37/37, overall
  P/R/F1 = 1.00**.

  Note: a perfect score means this corpus no longer discriminates against this
  model; it is saturated. To stay a useful fitness function the golden set
  needs harder cases (more cross-file/taint, adversarial negatives); 1.00 is a
  reason to grow the corpus, not to stop measuring.

- **2026-06-01: corpus hardened (golden 37 -> 47), discrimination restored.**
  Added 10 human-reviewed cases: cross-file pairs decided by provenance (an
  identical-sink path pair, raw-param vs basename-sanitized caller; an IDOR
  pair) and adversarial single-file cases (SQL concat split across variables, a
  bypassable substring SSRF allowlist, `hashlib.new("md5")` for passwords;
  `ast.literal_eval`, constant-only SQL concat, `textContent`). The eval harness
  gained a `context` field so cross-file cases feed the caller/callee to the
  verifier. New overall on 47 cases: **P 0.88 / R 1.00 / F1 0.94**; recall
  still perfect, precision down because the model over-flags all three
  safe-but-scary negatives (`literal_eval_safe`, `sql_constant_concat_safe`, and
  the cross-file `xfile_path_sanitized_safe`, all `input_validation`). That
  precision dip is intentional: these are the precision and cross-file
  provenance gaps P1 targets, now measurable instead of hidden by a saturated
  corpus.

- **2026-06-01: P1-04 taint gate clears the precision gap.** The new
  `--orchestrator taint` runs the verifier, then dismisses an input_validation
  finding only when the provenance engine proves (via the P1-02 vocabulary and a
  one-hop cross-file trace) that every sink receives a constant, sanitized, or
  trusted value. On the full 47-case golden set:
  `--orchestrator single` -> overall P 0.88 / R 1.00; `--orchestrator taint` ->
  overall **P 1.00 / R 1.00 / F1 1.00**, input_validation P 0.75 -> 1.00. All
  three false positives (`literal_eval_safe`, `sql_constant_concat_safe`, the
  cross-file `xfile_path_sanitized_safe`) cleared, recall unchanged; it clears
  the signed P1 gate (input_validation R >= 0.90 with P >= 0.95). `eval` now
  takes `--orchestrator`, so strategies are measurable against the golden set.
  Caveat: this corpus is single-file/synthetic; P1-05 validates on a real repo.

- **2026-06-01: P1-05 real-repo check (python-multipart CVE-2026-24486).**
  Scanned the vulnerable (0.0.21) and fixed (0.0.22) `multipart.py`; the fix is
  exactly `os.path.basename` before `os.path.splitext` of the upload filename,
  with `--orchestrator single` vs `taint`. Findings:
  - The taint gate was **inert** on this real file: it dismissed 0 findings in
    every run. `worst_sink_taint` never reached SAFE because the sink paths are
    built from instance/config attributes and streaming state, which the
    one-hop AST engine marks UNKNOWN (UNKNOWN is not SAFE). The gate stayed
    recall-safe (no false downgrades) but gave no precision gain here.
  - The verifier under-flagged the CVE on the 1872-line file (PARTIAL at most,
    never VULNERABLE, for both versions): a whole-file-review recall limit on
    large modules, independent of the gate.
  - Output drifted between identical-input runs: the proxy is not perfectly
    temperature 0.

  Conclusion (proposed, human-signed): the gate mechanism is validated on the
  golden set, but decisive real-world taint precision needs a deeper code graph
  (multi-hop + attribute/field tracking), not a looser gate; loosening UNKNOWN
  to "safe" would trade recall, which is the wrong trade for a security tool. P1
  ships the provenance engine and the conservative `taint` strategy; the deeper
  graph is future work. Real-repo thresholds remain unset pending that work.
