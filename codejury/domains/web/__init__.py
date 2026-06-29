"""The web domain: application security knowledge for web code, the default domain.

Its content root is this package directory, holding the `knowledge/`, `playbook/`, and
`detection.yaml` that codejury has always shipped. The review strategy that used to sit
in the engine lives here too as data: the pass lenses and the diff prompt's focus and
do-not-report blocks. The engine modules import these as their
defaults. This package imports only `codejury.domains.base`, so it stays a leaf the
engine can depend on without a cycle.
"""

from pathlib import Path

from codejury.domains.base import Domain

# the repo-review pass lenses: each pass leads with one class, the empty lens reviews every
# class. A named lens is a reliable focused pass, the empty catch-all is not, so every shipped
# high-impact class gets its own lens rather than relying on the catch-all to happen to surface
# it. Classes hunted by the identical activity share one lens, sql, nosql, command, and code all
# trace input into an interpreter under `injection`, the rest stay distinct by their sink.
WEB_LENSES = (
    "authorization",        # missing-authorization, IDOR
    "authentication",       # auth bypass, jwt-validation, insecure-session-management
    "replay",               # replay-attack
    "concurrency",          # race-condition
    "injection",            # sql, nosql, command, code
    "ssrf",                 # server-side-request-forgery
    "path-traversal",       # path-traversal, unrestricted-file-upload
    "deserialization",      # insecure-deserialization, prototype-pollution
    "xss",                  # cross-site-scripting
    "template-injection",   # server-side-template-injection
    "xxe",                  # xml-external-entity
    "csrf",                 # cross-site-request-forgery, cors-misconfiguration
    "open-redirect",        # open-redirect
    "smuggling",            # http-request-smuggling, http-response-splitting
    "cryptography",         # insecure-cryptography, hardcoded-secrets, insecure-transport
    "data-exposure",        # information-exposure
    "mass-assignment",      # mass-assignment
    "business-logic",       # business-logic
    "resource-exhaustion",  # resource-exhaustion
    "",
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
    diff_focus=WEB_DIFF_FOCUS,
    diff_do_not_report=WEB_DIFF_DO_NOT_REPORT,
)
