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
`json.loads` vs `pickle.loads`, host allowlist) -- the verifier did not
over-flag them.

## The three errors

| case | capability | label | predicted | type |
|---|---|---|---|---|
| `dependency_config_tls_verify_on_safe` | dependency_config | safe | VULNERABLE | FP |
| `deserialize_pickle_vuln` | input_validation | vuln | safe | FN |
| `ssrf_user_url_vuln` | input_validation | vuln | safe | FN |

- **FP** -- `requests.get(..., timeout=10)` with TLS verification at its secure
  default was read as a problem; the verifier is over-cautious about HTTP calls.
- **FN (x2)** -- both are taint-class sinks the verifier missed. The likely
  cause is a data gap: the `input_validation` capability YAML does not enumerate
  SSRF or insecure-deserialization anti-patterns, so the model is not primed to
  flag them. This is a capability-data / data-flow gap for P1/P3, not a prompt to
  grind (CLAUDE.md boundaries: taint precision is not fixed by prompt tuning).

## Determinism check

The eval run and an independent per-case re-run produced identical verdicts on
all 37 cases (same one FP, same two FN), consistent with temperature 0.

## Gate status

`Unlock P1` requires the per-capability baseline to be **recorded** -- done here.
The P1/P2/P3/P4 acceptance thresholds (X/Y/Z in ROADMAP) remain human-signed and
are filled in only on your sign-off.
