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


def _web_poc(**kw):
    """Build the web PoC writer lazily, so importing the domain never pulls a provider, only
    building a backend does."""
    from codejury.domains.web.poc import WebPoC
    return WebPoC(**kw)

# the repo-review pass lenses: each pass leads with one class, the empty lens reviews every
# class. A named lens is a reliable focused pass and the empty catch-all is not, so every shipped
# class gets a named lens rather than relying on the catch-all to surface it. Naming is one unified
# rule, no abbreviations, always the full name. A single-class lens is named exactly its class id,
# the CWE-style full name, so lens and class never drift. An umbrella lens leads a family hunted by
# one reading motion, covers several classes, and is named a neutral family noun that is never
# equal to any class id, so a lens name tells you at a glance whether it is one class or a family:
# injection covers sql, nosql, command, and code, authentication covers auth bypass, jwt, and
# session, authorization covers IDOR and missing checks, cryptography covers secrets, transport,
# and weak crypto, deserialization covers prototype pollution, cross-origin covers csrf and cors. A
# family becomes an umbrella only when a recognized neutral family name exists, so request smuggling
# and response splitting, and path traversal and file upload, stay single-class lenses rather than
# take an invented family name.
WEB_LENSES = (
    "authorization",
    "authentication",
    "replay-attack",
    "race-condition",
    "injection",
    "prompt-injection",
    "server-side-request-forgery",
    "path-traversal",
    "unrestricted-file-upload",
    "deserialization",
    "cross-site-scripting",
    "server-side-template-injection",
    "xml-external-entity",
    "cross-origin",
    "open-redirect",
    "http-request-smuggling",
    "http-response-splitting",
    "cryptography",
    "information-exposure",
    "security-misconfiguration",
    "mass-assignment",
    "business-logic",
    "resource-exhaustion",
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
    poc_backend=_web_poc,
)
