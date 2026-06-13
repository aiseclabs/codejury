"""The web domain: application security knowledge for web code, the default domain.

Its content root is this package directory, holding the `knowledge/`, `playbook/`, and
`detection.yaml` that codejury has always shipped. The review strategy that used to sit
in the engine lives here too as data: the pass lenses, the severity floor table, and the
diff prompt's focus and do-not-report blocks. The engine modules import these as their
defaults. This package imports only `codejury.domains.base`, so it stays a leaf the
engine can depend on without a cycle.
"""

from pathlib import Path

from codejury.domains.base import Domain

# the repo-review pass lenses: each pass leads with one, the empty lens reviews every class
WEB_LENSES = (
    "authorization",
    "replay",
    "concurrency",
    "data-exposure",
    "injection",
    "business-logic",
    "",
)

# the firm-rule severity floor table, regex and level pairs, floor_for matches it
WEB_SEVERITY_FLOORS = (
    (r"credential|secret|private[ _-]?key|signing[ _-]?key|bearer token|"
     r"api[ _-]?key|token.{0,20}(leak|logged|exposed|disclos)", "HIGH"),
    (r"\breplay\b|missing freshness|no (consumed )?nonce|no freshness", "HIGH"),
    (r"auth(entication)?[ _-]?bypass|signature forg|forge.{0,15}(signature|token|jwt)|"
     r"jwt forg|self.?cert", "HIGH"),
    (r"\bidor\b|insecure direct object|missing author|broken access|"
     r"cross.?(user|tenant|service).{0,20}(read|idor|access|disclos)", "MEDIUM"),
)

WEB_DIFF_FOCUS = """\
Hunt especially for high-impact, exploitable problems:
- Business logic flaws: approval/state-machine bypass, skipped steps, replay of a
  privileged action with no nonce or time window.
- Authorization: missing or bypassable checks, IDOR (cross-user, cross-tenant, or
  cross-service access to a resource by a user-supplied id).
- Authentication and signatures: auth bypass, JWT verification flaws, trusting a
  caller-supplied key as the trust anchor, unvalidated callback URLs.
- Injection: SQL, command, code/eval, template, deserialization of untrusted data.
- Mass assignment: a user-controlled body bound wholesale into a model.
- Secrets and crypto: hardcoded credentials, weak or misused crypto.
"""

WEB_DIFF_DO_NOT_REPORT = """\
Do NOT report, regardless of severity:
- Dependency or component CVEs.
- Style, naming, or general best-practice suggestions.
- Speculative issues you cannot tie to a concrete exploit in the code shown.
- Risks that only matter if a production config is leaked (do not assume the code
  shown reflects production configuration).
For input-driven issues, flag only when untrusted input can plausibly reach the
sink. A constant, a stored field, trusted config, or an operator-supplied CLI
argument is not attacker-controlled.
"""

WEB = Domain(
    name="web",
    content_root=Path(__file__).resolve().parent,
    lenses=WEB_LENSES,
    severity_floors=WEB_SEVERITY_FLOORS,
    diff_focus=WEB_DIFF_FOCUS,
    diff_do_not_report=WEB_DIFF_DO_NOT_REPORT,
)
